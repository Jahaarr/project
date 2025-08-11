from flask import Flask, request, jsonify, send_from_directory, session
from confluent_kafka import Producer, Consumer, KafkaError
import json
import datetime
from keycloak_config import KeycloakManager
import secrets
import threading
import time
from collections import defaultdict
import sqlite3
import os

app = Flask(__name__, static_folder='static')
app.secret_key = secrets.token_hex(16)

# Configuration Kafka
conf = {'bootstrap.servers': 'localhost:9092'}
producer = Producer(conf)

# Configuration Consumer pour les alertes
consumer_conf = {
    'bootstrap.servers': 'localhost:9092',
    'group.id': 'iam-alert-consumer',
    'auto.offset.reset': 'latest'
}
consumer = Consumer(consumer_conf)

# Initialiser Keycloak Manager
kc_manager = KeycloakManager()

# Base de données SQLite pour les alertes
def init_alerts_db():
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            alert_type TEXT,
            severity TEXT,
            message TEXT,
            details TEXT,
            timestamp TEXT,
            resolved BOOLEAN DEFAULT FALSE,
            resolved_by TEXT,
            resolved_at TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Initialiser la base de données au démarrage
init_alerts_db()

# Variables globales pour le monitoring
user_activities = defaultdict(list)
suspicious_patterns = []
active_alerts = []

def delivery_report(err, msg):
    if err is not None:
        print(f'Message delivery failed: {err}')
    else:
        print(f'Message delivered to {msg.topic()} [{msg.partition()}]')

def get_utc_now():
    return datetime.datetime.now(datetime.timezone.utc)

def detect_anomalies(log_data):
    """Détecter les anomalies dans les logs"""
    alerts = []
    user_id = log_data.get('userId')
    ip = log_data.get('ip')
    action = log_data.get('action')
    timestamp = log_data.get('timestamp')
    
    # Ajouter l'activité à l'historique
    user_activities[user_id].append({
        'ip': ip,
        'action': action,
        'timestamp': timestamp,
        'location': log_data.get('location', 'unknown')
    })
    
    # Garder seulement les 50 dernières activités par utilisateur
    if len(user_activities[user_id]) > 50:
        user_activities[user_id] = user_activities[user_id][-50:]
    
    recent_activities = user_activities[user_id][-10:]  # 10 dernières activités
    
    # 1. Détection de multiples tentatives de connexion échouées
    if action == 'login_failure':
        failed_attempts = [a for a in recent_activities if a['action'] == 'login_failure']
        if len(failed_attempts) >= 3:
            alerts.append({
                'type': 'multiple_failed_logins',
                'severity': 'high',
                'message': f'Multiple failed login attempts detected for user {user_id}',
                'details': f'{len(failed_attempts)} failed attempts in recent activity'
            })
    
    # 2. Détection de connexion depuis une nouvelle localisation
    if action == 'login_success':
        locations = set([a.get('location', 'unknown') for a in recent_activities if a['action'] == 'login_success'])
        current_location = log_data.get('location', 'unknown')
        if len(locations) > 1 and current_location not in [a.get('location') for a in recent_activities[:-1]]:
            alerts.append({
                'type': 'new_location_login',
                'severity': 'medium',
                'message': f'Login from new location detected for user {user_id}',
                'details': f'New location: {current_location}, Previous locations: {list(locations)}'
            })
    
    # 3. Détection de multiples IPs
    ips = set([a['ip'] for a in recent_activities])
    if len(ips) > 3:
        alerts.append({
            'type': 'multiple_ips',
            'severity': 'medium',
            'message': f'Multiple IP addresses used by user {user_id}',
            'details': f'IPs used: {list(ips)}'
        })
    
    # 4. Activité inhabituelle (trop d'actions en peu de temps)
    recent_timestamps = [datetime.datetime.fromisoformat(a['timestamp'].replace('Z', '+00:00')) for a in recent_activities]
    if len(recent_timestamps) >= 5:
        time_diff = (recent_timestamps[-1] - recent_timestamps[0]).total_seconds()
        if time_diff < 300:  # 5 minutes
            alerts.append({
                'type': 'rapid_activity',
                'severity': 'low',
                'message': f'Rapid activity detected for user {user_id}',
                'details': f'{len(recent_activities)} actions in {time_diff:.0f} seconds'
            })
    
    return alerts

def save_alert_to_db(user_id, alert):
    """Sauvegarder une alerte en base de données"""
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (user_id, alert_type, severity, message, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        user_id,
        alert['type'],
        alert['severity'],
        alert['message'],
        alert['details'],
        get_utc_now().isoformat()
    ))
    conn.commit()
    conn.close()

def get_user_role(username):
    """Récupérer le rôle de l'utilisateur depuis Keycloak"""
    try:
        user_info = kc_manager.get_user_info(username)
        # Pour cette démo, nous utilisons une logique simple
        # En production, vous récupéreriez les rôles depuis Keycloak
        if username == 'admin':
            return 'admin'
        return 'user'
    except:
        return 'user'

@app.route('/')
def home():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({
                'status': 'error',
                'message': 'Username and password required'
            }), 400
        
        # Authentification via Keycloak
        keycloak_session = kc_manager.authenticate_user(username, password)
        
        if keycloak_session:
            # Récupérer le rôle de l'utilisateur
            user_role = get_user_role(username)
            
            # Stocker la session Flask
            session['user'] = username
            session['role'] = user_role
            session['keycloak_token'] = keycloak_session['token']
            session['login_time'] = get_utc_now().isoformat()
            
            # Logger l'activité dans Keycloak
            kc_manager.log_user_activity(
                username=username,
                action='web_login',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', 'Unknown'),
                location=data.get('location', 'unknown')
            )
            
            # Créer le log pour Kafka
            login_log = {
                'userId': username,
                'action': 'login_success',
                'ip': request.remote_addr,
                'location': data.get('location', 'unknown'),
                'browser': data.get('browser', 'unknown'),
                'os': data.get('os', 'unknown'),
                'timezone': data.get('timezone', 'unknown'),
                'timestamp': get_utc_now().isoformat(),
                'sessionId': f"sess_{secrets.token_hex(8)}",
                'keycloak_user_id': keycloak_session['userinfo'].get('sub'),
                'keycloak_session': True,
                'server_timestamp': get_utc_now().isoformat(),
                'server_ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', 'Unknown'),
                'role': user_role
            }
            
            # Détecter les anomalies
            alerts = detect_anomalies(login_log)
            for alert in alerts:
                save_alert_to_db(username, alert)
            
            # Envoyer vers Kafka
            producer.produce(
                'iam-logs',
                value=json.dumps(login_log).encode('utf-8'),
                callback=delivery_report
            )
            producer.flush()
            
            return jsonify({
                'status': 'success',
                'message': 'Login successful',
                'user': username,
                'role': user_role,
                'keycloak_user_info': keycloak_session['userinfo'],
                'session_id': login_log['sessionId'],
                'alerts_count': len(alerts)
            }), 200
        
        else:
            # Log d'échec de connexion
            failure_log = {
                'userId': username,
                'action': 'login_failure',
                'ip': request.remote_addr,
                'timestamp': get_utc_now().isoformat(),
                'reason': 'invalid_credentials',
                'keycloak_session': False,
                'location': data.get('location', 'unknown')
            }
            
            # Détecter les anomalies pour les échecs de connexion
            alerts = detect_anomalies(failure_log)
            for alert in alerts:
                save_alert_to_db(username, alert)
            
            producer.produce(
                'iam-logs',
                value=json.dumps(failure_log).encode('utf-8'),
                callback=delivery_report
            )
            producer.flush()
            
            return jsonify({
                'status': 'error',
                'message': 'Invalid credentials'
            }), 401
            
    except Exception as e:
        print(f"Erreur lors de la connexion: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Login failed: {str(e)}'
        }), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    try:
        username = session.get('user')
        
        if username:
            kc_manager.log_user_activity(
                username=username,
                action='web_logout',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', 'Unknown')
            )
            
            logout_log = {
                'userId': username,
                'action': 'logout',
                'ip': request.remote_addr,
                'timestamp': get_utc_now().isoformat(),
                'session_duration': _calculate_session_duration(),
                'keycloak_session': True
            }
            
            producer.produce(
                'iam-logs',
                value=json.dumps(logout_log).encode('utf-8'),
                callback=delivery_report
            )
            producer.flush()
            
            session.clear()
            
            return jsonify({
                'status': 'success',
                'message': 'Logout successful'
            }), 200
        
        else:
            return jsonify({
                'status': 'error',
                'message': 'No active session'
            }), 400
            
    except Exception as e:
        print(f"Erreur lors de la déconnexion: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Logout failed: {str(e)}'
        }), 500

@app.route('/api/submit', methods=['POST'])
def submit_log():
    try:
        log = request.get_json()
        username = session.get('user')
        user_role = session.get('role', 'user')
        
        if not username:
            return jsonify({
                'status': 'error',
                'message': 'Not authenticated'
            }), 401
        
        enhanced_log = {
            **log,
            'server_timestamp': get_utc_now().isoformat(),
            'server_ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'keycloak_authenticated': True,
            'session_user': username,
            'role': user_role
        }
        
        # Détecter les anomalies
        alerts = detect_anomalies(enhanced_log)
        for alert in alerts:
            save_alert_to_db(username, alert)
        
        kc_manager.log_user_activity(
            username=username,
            action=log.get('action', 'activity'),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            location=log.get('location', 'unknown')
        )
        
        producer.produce(
            'iam-logs', 
            value=json.dumps(enhanced_log).encode('utf-8'), 
            callback=delivery_report
        )
        producer.flush()
        
        print(f"Activity log sent: {enhanced_log['userId']} - {enhanced_log['action']}")
        
        return jsonify({
            'status': 'success',
            'message': 'Log sent successfully',
            'timestamp': enhanced_log['server_timestamp'],
            'alerts_detected': len(alerts)
        }), 200
        
    except Exception as e:
        print(f"Error processing log: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to send log: {str(e)}'
        }), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Récupérer les alertes selon le rôle de l'utilisateur"""
    try:
        username = session.get('user')
        user_role = session.get('role', 'user')
        
        if not username:
            return jsonify({
                'status': 'error',
                'message': 'Not authenticated'
            }), 401
        
        conn = sqlite3.connect('alerts.db')
        cursor = conn.cursor()
        
        if user_role == 'admin':
            # Admin voit toutes les alertes
            cursor.execute('''
                SELECT * FROM alerts 
                ORDER BY timestamp DESC 
                LIMIT 100
            ''')
        else:
            # Utilisateur voit seulement ses alertes
            cursor.execute('''
                SELECT * FROM alerts 
                WHERE user_id = ? 
                ORDER BY timestamp DESC 
                LIMIT 50
            ''', (username,))
        
        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                'id': row[0],
                'user_id': row[1],
                'alert_type': row[2],
                'severity': row[3],
                'message': row[4],
                'details': row[5],
                'timestamp': row[6],
                'resolved': bool(row[7]),
                'resolved_by': row[8],
                'resolved_at': row[9]
            })
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'alerts': alerts,
            'role': user_role,
            'total_count': len(alerts)
        }), 200
        
    except Exception as e:
        print(f"Error getting alerts: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to get alerts: {str(e)}'
        }), 500

@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """Résoudre une alerte (admin uniquement)"""
    try:
        username = session.get('user')
        user_role = session.get('role', 'user')
        
        if not username:
            return jsonify({
                'status': 'error',
                'message': 'Not authenticated'
            }), 401
        
        if user_role != 'admin':
            return jsonify({
                'status': 'error',
                'message': 'Admin access required'
            }), 403
        
        conn = sqlite3.connect('alerts.db')
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE alerts 
            SET resolved = TRUE, resolved_by = ?, resolved_at = ?
            WHERE id = ?
        ''', (username, get_utc_now().isoformat(), alert_id))
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'message': 'Alert resolved successfully'
        }), 200
        
    except Exception as e:
        print(f"Error resolving alert: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to resolve alert: {str(e)}'
        }), 500

@app.route('/api/alerts/stats', methods=['GET'])
def get_alert_stats():
    """Statistiques des alertes (admin uniquement)"""
    try:
        username = session.get('user')
        user_role = session.get('role', 'user')
        
        if not username:
            return jsonify({
                'status': 'error',
                'message': 'Not authenticated'
            }), 401
        
        if user_role != 'admin':
            return jsonify({
                'status': 'error',
                'message': 'Admin access required'
            }), 403
        
        conn = sqlite3.connect('alerts.db')
        cursor = conn.cursor()
        
        # Statistiques générales
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total_alerts = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE resolved = FALSE')
        active_alerts = cursor.fetchone()[0]
        
        cursor.execute('SELECT severity, COUNT(*) FROM alerts GROUP BY severity')
        severity_stats = dict(cursor.fetchall())
        
        cursor.execute('SELECT alert_type, COUNT(*) FROM alerts GROUP BY alert_type')
        type_stats = dict(cursor.fetchall())
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'stats': {
                'total_alerts': total_alerts,
                'active_alerts': active_alerts,
                'resolved_alerts': total_alerts - active_alerts,
                'severity_breakdown': severity_stats,
                'type_breakdown': type_stats
            }
        }), 200
        
    except Exception as e:
        print(f"Error getting alert stats: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to get alert stats: {str(e)}'
        }), 500

@app.route('/api/user-sessions', methods=['GET'])
def get_user_sessions():
    try:
        username = session.get('user')
        
        if not username:
            return jsonify({
                'status': 'error',
                'message': 'Not authenticated'
            }), 401
        
        sessions = kc_manager.get_user_sessions(username)
        
        return jsonify({
            'status': 'success',
            'sessions': sessions,
            'username': username
        }), 200
        
    except Exception as e:
        print(f"Error getting sessions: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to get sessions: {str(e)}'
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': get_utc_now().isoformat(),
        'kafka_status': 'connected',
        'keycloak_status': 'integrated'
    }), 200

@app.route('/api/info', methods=['GET'])
def get_info():
    username = session.get('user')
    user_role = session.get('role', 'user')
    return jsonify({
        'server_time': get_utc_now().isoformat(),
        'client_ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'authenticated_user': username,
        'user_role': user_role,
        'keycloak_session': bool(username)
    }), 200

def _calculate_session_duration():
    try:
        login_time = session.get('login_time')
        if login_time:
            login_dt = datetime.datetime.fromisoformat(login_time)
            if login_dt.tzinfo is None:
                login_dt = login_dt.replace(tzinfo=datetime.timezone.utc)
            duration = get_utc_now() - login_dt
            return duration.total_seconds()
        return 0
    except:
        return 0

@app.route('/api/setup-keycloak', methods=['POST'])
def setup_keycloak():
    try:
        from keycloak_config import setup_test_users
        
        success = setup_test_users()
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Keycloak setup completed successfully'
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Keycloak setup failed'
            }), 500
            
    except Exception as e:
        print(f"Error setting up Keycloak: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Setup failed: {str(e)}'
        }), 500

if __name__ == '__main__':
    print("Starting IAM Flask Server with Keycloak integration and Anomaly Detection...")
    print("Kafka Bootstrap Servers:", conf['bootstrap.servers'])
    print("Keycloak Server:", kc_manager.server_url)
    print("Keycloak Realm:", kc_manager.realm_name)
    print("Alert Database: alerts.db")
    
    app.run(host='0.0.0.0', port=5000, debug=True)