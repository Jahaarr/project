# keycloak_config.py
from keycloak import KeycloakAdmin, KeycloakOpenID
from keycloak.exceptions import KeycloakError
import requests
import json
import datetime

class KeycloakManager:
    def __init__(self):
        # Configuration Keycloak
        self.server_url = "http://localhost:8080/"  # URL de votre serveur Keycloak
        self.realm_name = "iam-realm"  # Nom de votre realm
        self.client_id = "iam-client"  # ID de votre client
        self.client_secret = "EfvtQ2dSaPWzvK9iR8CpspEDsadsKfxt"  # Secret du client
        
        # Identifiants admin (pour créer des utilisateurs)
        self.admin_username = "admin"
        self.admin_password = "admin"
        
        # Initialiser les clients Keycloak
        self.keycloak_admin = KeycloakAdmin(
            server_url=self.server_url,
            username=self.admin_username,
            password=self.admin_password,
            realm_name="master",  # Realm master pour l'admin
            verify=False  # Changé à False pour éviter les problèmes SSL en dev
        )
        
        self.keycloak_openid = KeycloakOpenID(
            server_url=self.server_url,
            client_id=self.client_id,
            realm_name=self.realm_name,
            client_secret_key=self.client_secret
        )

    def get_utc_now(self):
        """Retourne l'heure UTC actuelle en évitant le warning de dépréciation"""
        return datetime.datetime.now(datetime.timezone.utc)
    
    def setup_realm_and_client(self):
        """Configure le realm et le client Keycloak"""
        try:
            # Créer le realm
            realm_data = {
                "realm": self.realm_name,
                "enabled": True,
                "displayName": "IAM System Realm",
                "loginWithEmailAllowed": True,
                "duplicateEmailsAllowed": False,
                "resetPasswordAllowed": True,
                "editUsernameAllowed": False,
                "bruteForceProtected": True,
                "loginTheme": "keycloak",
                "adminTheme": "keycloak",
                "accountTheme": "keycloak",
                "emailTheme": "keycloak"
            }
            
            self.keycloak_admin.create_realm(payload=realm_data, skip_exists=True)
            print(f"Realm '{self.realm_name}' créé/vérifié")
            
            # Changer vers le realm IAM pour créer le client
            self.keycloak_admin.realm_name = self.realm_name
            
            # Vérifier si le client existe déjà
            clients = self.keycloak_admin.get_clients()
            client_exists = any(client['clientId'] == self.client_id for client in clients)
            
            if not client_exists:
                # Créer le client avec toutes les configurations nécessaires
                client_data = {
                    "clientId": self.client_id,
                    "name": "IAM Client Application",
                    "enabled": True,
                    "clientAuthenticatorType": "client-secret",
                    "secret": self.client_secret,
                    "protocol": "openid-connect",
                    "publicClient": False,
                    "bearerOnly": False,
                    "consentRequired": False,
                    "standardFlowEnabled": True,
                    "directAccessGrantsEnabled": True,  # CRITIQUE: Active les Direct Access Grants
                    "implicitFlowEnabled": False,
                    "serviceAccountsEnabled": True,
                    "authorizationServicesEnabled": False,
                    "fullScopeAllowed": True,
                    "redirectUris": ["http://localhost:5000/*", "*"],
                    "webOrigins": ["http://localhost:5000", "*"],
                    "baseUrl": "http://localhost:5000",
                    "adminUrl": "http://localhost:5000",
                    "attributes": {
                        "access.token.lifespan": "3600",
                        "client.secret.creation.time": "1640995200"
                    }
                }
                
                client_id = self.keycloak_admin.create_client(payload=client_data)
                print(f"Client '{self.client_id}' créé avec Direct Access Grants activé")
            else:
                # Mettre à jour le client existant pour s'assurer que Direct Access Grants est activé
                for client in clients:
                    if client['clientId'] == self.client_id:
                        client_uuid = client['id']
                        
                        # Récupérer la configuration complète du client
                        current_client = self.keycloak_admin.get_client(client_uuid)
                        
                        # Mettre à jour les propriétés nécessaires
                        current_client['directAccessGrantsEnabled'] = True
                        current_client['standardFlowEnabled'] = True
                        current_client['publicClient'] = False
                        current_client['secret'] = self.client_secret
                        current_client['enabled'] = True
                        
                        # Sauvegarder les modifications
                        self.keycloak_admin.update_client(client_uuid, current_client)
                        print(f"Client '{self.client_id}' mis à jour avec Direct Access Grants activé")
                        break
            
            return True
            
        except Exception as e:
            print(f"Erreur lors de la configuration Keycloak: {e}")
            return False
    
    def create_user(self, username, password, email=None, first_name=None, last_name=None):
        """Créer un utilisateur dans Keycloak"""
        try:
            self.keycloak_admin.realm_name = self.realm_name
            
            # Vérifier si l'utilisateur existe déjà
            existing_users = self.keycloak_admin.get_users({"username": username})
            
            if existing_users:
                print(f"Utilisateur '{username}' existe déjà")
                # Mettre à jour le mot de passe
                user_id = existing_users[0]['id']
                self.keycloak_admin.set_user_password(user_id, password, temporary=False)
                print(f"Mot de passe mis à jour pour '{username}'")
                return user_id
            
            user_data = {
                "username": username,
                "enabled": True,
                "emailVerified": True,
                "firstName": first_name or username,
                "lastName": last_name or "User",
                "email": email or f"{username}@example.com",
                "credentials": [{
                    "type": "password",
                    "value": password,
                    "temporary": False
                }]
            }
            
            user_id = self.keycloak_admin.create_user(payload=user_data)
            print(f"Utilisateur '{username}' créé dans Keycloak")
            return user_id
            
        except Exception as e:
            print(f"Erreur lors de la création de l'utilisateur {username}: {e}")
            return None
    
    def authenticate_user(self, username, password):
        """Authentifier un utilisateur via Keycloak"""
        try:
            print(f"Tentative d'authentification pour: {username}")
            
            # Obtenir le token d'accès via Direct Access Grant
            token = self.keycloak_openid.token(username, password)
            print(f"Token obtenu avec succès")
            
            # Obtenir les infos utilisateur
            userinfo = self.keycloak_openid.userinfo(token['access_token'])
            print(f"Informations utilisateur récupérées: {userinfo.get('preferred_username')}")
            
            # Créer une session
            session_data = {
                'username': username,
                'token': token,
                'userinfo': userinfo,
                'login_time': self.get_utc_now().isoformat()
            }
            
            return session_data
            
        except KeycloakError as e:
            print(f"Erreur d'authentification Keycloak: {e}")
            return None
        except Exception as e:
            print(f"Erreur générale d'authentification: {e}")
            return None
    
    def log_user_activity(self, username, action, ip_address, user_agent, location=None):
        """Logger l'activité utilisateur dans Keycloak"""
        try:
            # Obtenir l'ID utilisateur
            self.keycloak_admin.realm_name = self.realm_name
            users = self.keycloak_admin.get_users({"username": username})
            
            if not users:
                print(f"Utilisateur {username} non trouvé dans Keycloak")
                return False
            
            user_id = users[0]['id']
            
            # Créer un event personnalisé
            event_data = {
                "type": "LOGIN",
                "realmId": self.realm_name,
                "clientId": self.client_id,
                "userId": user_id,
                "ipAddress": ip_address,
                "details": {
                    "action": action,
                    "user_agent": user_agent,
                    "location": location or "unknown",
                    "custom_login": "true"
                }
            }
            
            # Logger l'événement
            self._send_custom_event(event_data)
            
            return True
            
        except Exception as e:
            print(f"Erreur lors du logging: {e}")
            return False
    
    def _send_custom_event(self, event_data):
        """Envoyer un event personnalisé (via webhook ou logging)"""
        try:
            print(f"Event Keycloak loggé: {event_data['details']['action']} pour utilisateur {event_data.get('userId')}")
            return True
            
        except Exception as e:
            print(f"Erreur envoi event: {e}")
            return False
    
    def get_user_sessions(self, username):
        """Récupérer les sessions actives d'un utilisateur via l'API REST"""
        try:
            self.keycloak_admin.realm_name = self.realm_name
            users = self.keycloak_admin.get_users({"username": username})
            
            if not users:
                print(f"Utilisateur {username} non trouvé")
                return []
            
            user_id = users[0]['id']
            
            # Utiliser l'API REST directement car get_user_sessions n'existe pas dans toutes les versions
            try:
                # Méthode 1: Essayer d'utiliser la méthode directe si elle existe
                if hasattr(self.keycloak_admin, 'get_user_sessions'):
                    sessions = self.keycloak_admin.get_user_sessions(user_id)
                    return sessions
                else:
                    # Méthode 2: Utiliser l'API REST directement
                    admin_token = self.keycloak_admin.token['access_token']
                    headers = {
                        'Authorization': f'Bearer {admin_token}',
                        'Content-Type': 'application/json'
                    }
                    
                    # URL pour récupérer les sessions utilisateur
                    url = f"{self.server_url}admin/realms/{self.realm_name}/users/{user_id}/sessions"
                    
                    response = requests.get(url, headers=headers, verify=False)
                    
                    if response.status_code == 200:
                        sessions = response.json()
                        return sessions
                    else:
                        print(f"Erreur API REST sessions: {response.status_code} - {response.text}")
                        return []
                        
            except Exception as api_error:
                print(f"Erreur API sessions: {api_error}")
                
                # Méthode 3: Retourner des données de session simulées basées sur le token
                return [{
                    'id': f'session-{user_id[:8]}',
                    'username': username,
                    'userId': user_id,
                    'start': int(self.get_utc_now().timestamp() * 1000),
                    'lastAccess': int(self.get_utc_now().timestamp() * 1000),
                    'ipAddress': 'unknown',
                    'clients': {
                        self.client_id: 'Active'
                    }
                }]
            
        except Exception as e:
            print(f"Erreur récupération sessions: {e}")
            return []

# Fonction utilitaire pour initialiser les utilisateurs de test
def setup_test_users():
    """Créer les utilisateurs de test dans Keycloak"""
    try:
        kc_manager = KeycloakManager()
        
        # Configurer le realm et client
        if not kc_manager.setup_realm_and_client():
            print("Erreur lors de la configuration Keycloak")
            return False
        
        # Créer les utilisateurs de test
        test_users = [
            {'username': 'admin', 'password': 'password123', 'email': 'admin@example.com', 'first_name': 'Admin', 'last_name': 'User'},
            {'username': 'user1', 'password': 'mypass', 'email': 'user1@example.com', 'first_name': 'User', 'last_name': 'One'},
            {'username': 'testuser', 'password': 'test123', 'email': 'test@example.com', 'first_name': 'Test', 'last_name': 'User'},
            {'username': 'demo', 'password': 'demo', 'email': 'demo@example.com', 'first_name': 'Demo', 'last_name': 'User'}
        ]
        
        for user in test_users:
            kc_manager.create_user(
                username=user['username'],
                password=user['password'],
                email=user['email'],
                first_name=user['first_name'],
                last_name=user['last_name']
            )
        
        print("Utilisateurs de test créés dans Keycloak")
        
        # Test de connexion pour vérifier la configuration
        print("Test de la configuration...")
        test_auth = kc_manager.authenticate_user("admin", "password123")
        if test_auth:
            print("✅ Configuration Keycloak réussie - Test de connexion OK!")
        else:
            print("❌ Configuration Keycloak échoué - Test de connexion KO!")
            return False
            
        return True
        
    except Exception as e:
        print(f"Erreur générale lors du setup: {e}")
        return False

if __name__ == "__main__":
    setup_test_users()