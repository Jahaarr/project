# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copier les fichiers de requirements
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code de l'application
COPY . .

# Exposer le port
EXPOSE 5000

# Variables d'environnement par défaut
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV KAFKA_BOOTSTRAP_SERVERS=localhost:9092
ENV KEYCLOAK_SERVER_URL=http://localhost:8080/
ENV KEYCLOAK_REALM=iam-realm
ENV KEYCLOAK_CLIENT_ID=iam-client

# Commande pour démarrer l'application
CMD ["python", "app.py"]