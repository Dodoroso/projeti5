# Utiliser une image Python
FROM python:3.10

# Définir le répertoire de travail dans le conteneur
WORKDIR /app

# Copier le fichier requirements.txt
COPY requirements.txt .

# Installer les dépendances nécessaires
RUN pip install --no-cache-dir -r requirements.txt

# Copier tous les fichiers de ton projet
COPY . .

# Exposer le port utilisé par FastAPI (8000 dans ce cas)
EXPOSE 8000

# Commande pour démarrer l'API avec Uvicorn
CMD ["uvicorn", "API_projet_I5:app", "--host", "0.0.0.0", "--port", "8000"]