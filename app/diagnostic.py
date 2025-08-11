#!/usr/bin/env python3
"""
Script de diagnostic pour le système IAM
Vérifie les services et configure Keycloak
"""

import requests
import json
import time
import sys

BASE_URL = "http://localhost:5000"

def check_service_health():
    """Vérifier la santé des services"""
    print("🔍 Vérification des services...")
    
    try:
        response = requests.get(f"{BASE_URL}/api/health", timeout=5)
        if response.status_code == 200:
            print("✅ Service Flask OK")
            data = response.json()
            print(f"   Kafka Status: {data.get('kafka_status', 'unknown')}")
            print(f"   Keycloak Status: {data.get('keycloak_status', 'unknown')}")
            return True
        else:
            print(f"❌ Service Flask KO - Status: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Service Flask non accessible - Vérifiez docker-compose")
        print("   Commande: docker-compose up -d")
        return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

def check_docker_services():
    """Vérifier que les services Docker sont démarrés"""
    print("🐳 Vérification des conteneurs Docker...")
    
    services = [
        ("Keycloak", "http://localhost:8080"),
        ("Kafka UI", "http://localhost:8081"), 
        ("PostgreSQL", "localhost:5432")  # Juste pour info
    ]
    
    for name, url in services[:2]:  # Seulement HTTP
        try:
            response = requests.get(url, timeout=3)
            print(f"✅ {name} accessible")
        except:
            print(f"❌ {name} non accessible sur {url}")
    
    print("   PostgreSQL sur port 5432 (non testé via HTTP)")

def setup_keycloak():
    """Configurer Keycloak avec les utilisateurs de test"""
    print("\n🔧 Configuration de Keycloak...")
    
    # Attendre que Keycloak soit prêt
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.post(f"{BASE_URL}/api/setup-keycloak", timeout=30)
            if response.status_code == 200:
                print("✅ Keycloak configuré avec succès")
                return True
            else:
                print(f"❌ Échec configuration Keycloak - Status: {response.status_code}")
                if attempt < max_retries - 1:
                    print(f"   Tentative {attempt + 2}/{max_retries} dans 5 secondes...")
                    time.sleep(5)
        except Exception as e:
            print(f"❌ Erreur configuration Keycloak: {e}")
            if attempt < max_retries - 1:
                print(f"   Tentative {attempt + 2}/{max_retries} dans 5 secondes...")
                time.sleep(5)
    
    return False

def test_login(username="admin", password="password123"):
    """Tester la connexion"""
    print(f"\n🔐 Test de connexion avec {username}...")
    
    login_data = {
        "username": username,
        "password": password,
        "location": "Casablanca, Morocco",
        "browser": "Python-Test",
        "os": "Linux",
        "timezone": "Africa/Casablanca"
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/login", 
            json=login_data,
            timeout=10
        )
        
        if response.status_code == 200:
            print("✅ Connexion réussie")
            data = response.json()
            print(f"   Utilisateur: {data.get('user')}")
            print(f"   Rôle: {data.get('role')}")
            print(f"   Session ID: {data.get('session_id')}")
            print(f"   Alertes: {data.get('alerts_count', 0)}")
            
            # Extraire les cookies de session
            return response.cookies
        else:
            print(f"❌ Échec connexion - Status: {response.status_code}")
            print(f"   Response: {response.text}")
            return None
    except Exception as e:
        print(f"❌ Erreur connexion: {e}")
        return None

def test_alerts(cookies):
    """Tester la récupération des alertes"""
    print("\n🚨 Test des alertes...")
    
    try:
        response = requests.get(f"{BASE_URL}/api/alerts", cookies=cookies, timeout=5)
        if response.status_code == 200:
            data = response.json()
            alerts_count = len(data.get('alerts', []))
            print(f"✅ Alertes accessibles - {alerts_count} alertes trouvées")
            print(f"   Rôle utilisateur: {data.get('role')}")
            return True
        else:
            print(f"❌ Échec récupération alertes - Status: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur alertes: {e}")
        return False

def test_kafka_send(cookies):
    """Tester l'envoi vers Kafka"""
    print("\n📤 Test envoi vers Kafka...")
    
    test_log = {
        "userId": "test-diagnostic",
        "action": "diagnostic_test",
        "ip": "192.168.1.100",
        "location": "Casablanca, Morocco",
        "browser": "Chrome",
        "os": "Linux",
        "timezone": "Africa/Casablanca",
        "timestamp": "2024-12-19T10:30:00Z",
        "sessionId": "diagnostic-session-123"
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/submit",
            json=test_log,
            cookies=cookies,
            timeout=10
        )
        
        if response.status_code == 200:
            print("✅ Envoi Kafka réussi")
            data = response.json()
            print(f"   Status: {data.get('status')}")
            print(f"   Message: {data.get('message')}")
            print(f"   Alertes détectées: {data.get('alerts_detected', 0)}")
            return True
        else:
            print(f"❌ Échec envoi Kafka - Status: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Erreur envoi Kafka: {e}")
        return False

def test_logout(cookies):
    """Tester la déconnexion"""
    print("\n🚪 Test de déconnexion...")
    
    try:
        response = requests.post(f"{BASE_URL}/api/logout", cookies=cookies, timeout=5)
        if response.status_code == 200:
            print("✅ Déconnexion réussie")
            return True
        else:
            print(f"❌ Échec déconnexion - Status: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur déconnexion: {e}")
        return False

def check_kafka_topic():
    """Vérifier si le topic Kafka existe via l'interface web"""
    print("\n📊 Vérification du topic Kafka...")
    
    try:
        # Kafka UI est sur le port 8081
        response = requests.get("http://localhost:8081", timeout=5)
        if response.status_code == 200:
            print("✅ Kafka UI accessible sur http://localhost:8081")
            print("   Consultez l'interface pour voir le topic 'iam-logs'")
            return True
        else:
            print(f"❌ Kafka UI retourne le status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Kafka UI non accessible - Vérifiez docker-compose")
        print("   Le service kafka-ui est-il démarré?")
        return False
    except Exception as e:
        print(f"❌ Erreur Kafka UI: {e}")
        return False

def run_full_test():
    """Exécuter tous les tests"""
    print("=" * 60)
    print("🚀 DIAGNOSTIC SYSTÈME IAM COMPLET")
    print("=" * 60)
    
    success_count = 0
    total_tests = 7
    
    # 1. Vérifier Docker
    check_docker_services()
    
    # 2. Vérifier les services
    if check_service_health():
        success_count += 1
    else:
        print("\n❌ Les services de base ne sont pas accessibles")
        print("   Vérifiez que docker-compose est démarré:")
        print("   $ docker-compose up -d")
        return False
    
    # 3. Configurer Keycloak
    if setup_keycloak():
        success_count += 1
    else:
        print("\n❌ Configuration Keycloak échouée")
        return False
    
    # 4. Tester la connexion
    cookies = test_login()
    if cookies:
        success_count += 1
    else:
        print("\n❌ Test de connexion échoué")
        return False
    
    # 5. Tester les alertes
    if test_alerts(cookies):
        success_count += 1
    
    # 6. Tester Kafka
    if test_kafka_send(cookies):
        success_count += 1
    
    # 7. Tester la déconnexion
    if test_logout(cookies):
        success_count += 1
    
    # 8. Vérifier Kafka UI
    if check_kafka_topic():
        success_count += 1
    
    print("\n" + "=" * 60)
    print(f"📊 RÉSULTATS: {success_count}/{total_tests} tests réussis")
    
    if success_count >= 5:
        print("✅ DIAGNOSTIC TERMINÉ AVEC SUCCÈS")
    else:
        print("⚠️  DIAGNOSTIC PARTIEL - Quelques problèmes détectés")
    
    print("=" * 60)
    print_usage_instructions()
    
    return success_count >= 5

def print_usage_instructions():
    """Afficher les instructions d'utilisation"""
    print("\n🎯 INSTRUCTIONS POUR L'INTERFACE WEB:")
    print("1. Allez sur http://localhost:5000")
    print("2. Cliquez sur 'Generate Activity Log' pour créer un log")
    print("3. Connectez-vous avec admin/password123")
    print("4. Cliquez sur 'Send to Kafka'")
    print("5. Vérifiez les logs dans la console")
    print("\n📊 INTERFACES UTILES:")
    print("- Application: http://localhost:5000")
    print("- Kafka UI: http://localhost:8081")
    print("- Keycloak: http://localhost:8080 (admin/admin)")
    print("\n🔧 UTILISATEURS DE TEST:")
    print("- admin / password123 (administrateur)")
    print("- user1 / mypass (utilisateur)")
    print("- testuser / test123 (test)")
    print("- demo / demo (démo)")

def main():
    """Fonction principale"""
    if len(sys.argv) > 1 and sys.argv[1] == "--quick":
        print("🚀 DIAGNOSTIC RAPIDE")
        print("=" * 40)
        check_service_health()
        cookies = test_login()
        if cookies:
            test_kafka_send(cookies)
            test_logout(cookies)
    else:
        run_full_test()

if __name__ == "__main__":
    main()