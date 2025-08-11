from confluent_kafka import Consumer, KafkaError
from sklearn.ensemble import IsolationForest
import json
import numpy as np
import datetime
from collections import defaultdict
import hashlib

# Configuration Kafka
conf = {
    'bootstrap.servers': 'localhost:9092',
    'group.id': 'anomaly-group',
    'auto.offset.reset': 'earliest'
}
consumer = Consumer(conf)
consumer.subscribe(['iam-logs'])

# Initialiser IsolationForest
rcf = IsolationForest(contamination=0.1, random_state=42)

# Stockage des données
data_buffer = []
user_sessions = defaultdict(list)
ip_history = defaultdict(list)

def get_utc_now():
    """Retourne l'heure UTC actuelle en évitant le warning de dépréciation"""
    return datetime.datetime.now(datetime.timezone.utc)

def extract_features(log):
    """Extraire des features numériques du log pour l'analyse d'anomalies"""
    features = []
    
    try:
        # Feature 1: Heure de la journée (0-23)
        if 'timestamp' in log:
            hour = datetime.datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00')).hour
            features.append(hour)
        else:
            features.append(12)  # Default
        
        # Feature 2: IP (dernier octet)
        if 'ip' in log and log['ip'] != 'unknown':
            try:
                ip_parts = log['ip'].split('.')
                if len(ip_parts) == 4:
                    features.append(int(ip_parts[-1]))
                else:
                    features.append(0)
            except:
                features.append(0)
        else:
            features.append(0)
        
        # Feature 3: Hash du user ID (pour détecter des patterns)
        if 'userId' in log:
            user_hash = int(hashlib.md5(log['userId'].encode()).hexdigest()[:8], 16) % 1000
            features.append(user_hash)
        else:
            features.append(0)
        
        # Feature 4: Jour de la semaine (0-6)
        if 'timestamp' in log:
            day_of_week = datetime.datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00')).weekday()
            features.append(day_of_week)
        else:
            features.append(0)
        
        # Feature 5: Length of session ID (peut indiquer des patterns anormaux)
        if 'sessionId' in log:
            features.append(len(log['sessionId']))
        else:
            features.append(10)  # Default length
        
        # Feature 6: Browser type (encoded)
        browser_map = {'Chrome': 1, 'Firefox': 2, 'Safari': 3, 'Edge': 4, 'Unknown': 0}
        browser = log.get('browser', 'Unknown')
        features.append(browser_map.get(browser, 0))
        
        # Feature 7: OS type (encoded)
        os_map = {'Windows': 1, 'macOS': 2, 'Linux': 3, 'Android': 4, 'iOS': 5, 'Unknown': 0}
        os = log.get('os', 'Unknown')
        features.append(os_map.get(os, 0))
        
    except Exception as e:
        print(f"Error extracting features: {e}")
        # Return default features if extraction fails
        features = [12, 0, 0, 0, 10, 0, 0]
    
    return features

def detect_behavioral_anomalies(log):
    """Détection d'anomalies comportementales"""
    anomalies = []
    
    user_id = log.get('userId')
    ip = log.get('ip')
    timestamp = log.get('timestamp')
    
    if not user_id or not ip or not timestamp:
        return anomalies
    
    # Vérifier les connexions depuis des IP multiples
    if user_id in user_sessions:
        recent_ips = [session.get('ip') for session in user_sessions[user_id][-5:]]
        unique_ips = len(set(recent_ips))
        if unique_ips > 3:
            anomalies.append(f"Multiple IPs detected for user {user_id}: {unique_ips} different IPs")
    
    # Vérifier les connexions rapides depuis des locations différentes
    if user_id in user_sessions and len(user_sessions[user_id]) > 1:
        last_session = user_sessions[user_id][-1]
        current_location = log.get('location', 'unknown')
        last_location = last_session.get('location', 'unknown')
        
        if current_location != last_location and current_location != 'unknown' and last_location != 'unknown':
            try:
                last_time = datetime.datetime.fromisoformat(last_session['timestamp'].replace('Z', '+00:00'))
                current_time = datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_diff = (current_time - last_time).total_seconds() / 60  # minutes
                
                if time_diff < 30:  # Moins de 30 minutes entre deux locations différentes
                    anomalies.append(f"Rapid location change for user {user_id}: {last_location} -> {current_location} in {time_diff:.1f} minutes")
            except:
                pass
    
    # Vérifier les connexions en dehors des heures normales
    try:
        hour = datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00')).hour
        if hour < 6 or hour > 22:  # Connexions entre 22h et 6h
            anomalies.append(f"Off-hours login for user {user_id} at {hour}:00")
    except:
        pass
    
    # Nouvelle détection: Tentatives de connexion répétées échouées
    if user_id in user_sessions:
        recent_actions = [session.get('action') for session in user_sessions[user_id][-5:]]
        failed_attempts = recent_actions.count('login_failure')
        if failed_attempts >= 3:
            anomalies.append(f"Multiple failed login attempts for user {user_id}: {failed_attempts} failures")
    
    # Nouvelle détection: Changement soudain de User-Agent
    if user_id in user_sessions and len(user_sessions[user_id]) > 1:
        last_user_agent = user_sessions[user_id][-1].get('user_agent', 'unknown')
        current_user_agent = log.get('user_agent', 'unknown')
        
        if (last_user_agent != 'unknown' and current_user_agent != 'unknown' and 
            last_user_agent != current_user_agent):
            anomalies.append(f"User-Agent change detected for user {user_id}")
    
    return anomalies

def analyze_log(log):
    """Analyse complète du log"""
    print(f"\n--- Analyzing log for user: {log.get('userId', 'Unknown')} ---")
    
    # Extraction des features
    features = extract_features(log)
    print(f"Extracted features: {features}")
    
    # Ajouter aux données pour l'analyse ML
    data_buffer.append(features)
    
    # Garder un buffer de 50 logs maximum
    if len(data_buffer) > 50:
        data_buffer.pop(0)
    
    # Analyse ML si on a assez de données
    ml_anomaly = False
    anomaly_score = 0.0
    if len(data_buffer) >= 10:
        X = np.array(data_buffer)
        try:
            predictions = rcf.fit_predict(X)
            scores = rcf.decision_function(X)
            if predictions[-1] == -1:  # Le dernier log est une anomalie
                ml_anomaly = True
                anomaly_score = scores[-1]
                print(f"🚨 ML ANOMALY DETECTED! Score: {anomaly_score:.3f}")
        except Exception as e:
            print(f"ML analysis error: {e}")
    
    # Détection d'anomalies comportementales
    behavioral_anomalies = detect_behavioral_anomalies(log)
    
    # Sauvegarder la session
    user_id = log.get('userId')
    if user_id:
        user_sessions[user_id].append(log)
        # Garder seulement les 10 dernières sessions par utilisateur
        if len(user_sessions[user_id]) > 10:
            user_sessions[user_id].pop(0)
    
    # Afficher les résultats
    if ml_anomaly or behavioral_anomalies:
        print("🔴 ANOMALIES DETECTED:")
        if ml_anomaly:
            print(f"  - Machine Learning anomaly detected (score: {anomaly_score:.3f})")
        for anomaly in behavioral_anomalies:
            print(f"  - {anomaly}")
        
        # Log détaillé de l'anomalie
        anomaly_report = {
            'timestamp': get_utc_now().isoformat(),
            'user_id': log.get('userId'),
            'ip': log.get('ip'),
            'location': log.get('location'),
            'ml_anomaly': ml_anomaly,
            'ml_anomaly_score': float(anomaly_score) if ml_anomaly else None,
            'behavioral_anomalies': behavioral_anomalies,
            'risk_level': calculate_risk_level(ml_anomaly, behavioral_anomalies, anomaly_score),
            'features': features,
            'original_log': log
        }
        
        print(f"Full anomaly report: {json.dumps(anomaly_report, indent=2)}")
        
        # Envoyer une alerte si le niveau de risque est élevé
        if anomaly_report['risk_level'] in ['HIGH', 'CRITICAL']:
            send_security_alert(anomaly_report)
            
    else:
        print("✅ No anomalies detected")

def calculate_risk_level(ml_anomaly, behavioral_anomalies, anomaly_score):
    """Calculer le niveau de risque basé sur les anomalies détectées"""
    risk_score = 0
    
    if ml_anomaly:
        # Score ML négatif = plus anormal
        risk_score += abs(anomaly_score) * 10
    
    # Chaque anomalie comportementale ajoute au risque
    risk_score += len(behavioral_anomalies) * 2
    
    # Certaines anomalies sont plus critiques
    critical_patterns = ['Multiple failed login attempts', 'Multiple IPs detected', 'Rapid location change']
    for anomaly in behavioral_anomalies:
        for pattern in critical_patterns:
            if pattern in anomaly:
                risk_score += 5
                break
    
    if risk_score >= 15:
        return 'CRITICAL'
    elif risk_score >= 10:
        return 'HIGH'
    elif risk_score >= 5:
        return 'MEDIUM'
    else:
        return 'LOW'

def send_security_alert(anomaly_report):
    """Envoyer une alerte de sécurité (placeholder pour intégration SIEM)"""
    print(f"🚨🚨 SECURITY ALERT - {anomaly_report['risk_level']} RISK 🚨🚨")
    print(f"User: {anomaly_report['user_id']}")
    print(f"IP: {anomaly_report['ip']}")
    print(f"Time: {anomaly_report['timestamp']}")
    print(f"Anomalies: {len(anomaly_report['behavioral_anomalies']) + (1 if anomaly_report['ml_anomaly'] else 0)}")
    
    # Ici vous pourriez intégrer avec:
    # - SIEM (Splunk, ELK, QRadar)
    # - Notification (Slack, Email, SMS)
    # - Ticketing system (Jira, ServiceNow)
    # - Incident response platform

# Boucle principale
print("Starting Enhanced IAM Anomaly Detection Consumer...")
print("Listening for logs on 'iam-logs' topic...")
print("Features: ML anomaly detection, behavioral analysis, risk scoring")

try:
    while True:
        msg = consumer.poll(1.0)
        
        if msg is None:
            continue
            
        if msg.error():
            if msg.error().code() == KafkaError._PARTITION_EOF:
                print('Reached end of partition')
                continue
            else:
                print(f"Consumer error: {msg.error()}")
                continue
        
        try:
            # Décoder le message
            log = json.loads(msg.value().decode('utf-8'))
            
            # Analyser le log
            analyze_log(log)
            
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
        except Exception as e:
            print(f"Processing error: {e}")

except KeyboardInterrupt:
    print("\nShutting down consumer...")
finally:
    consumer.close()
    print("Consumer closed.")