import httpx
from fastapi import FastAPI, HTTPException, Depends,Query,Body
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
import aiomysql  # Bibliothèque pour interagir avec MySQL de manière asynchrone
import re
from datetime import datetime, timedelta
from jose import JWTError, jwt
from datetime import timedelta

# Configuration JWT
SECRET_KEY = "votre_cle_secrete_ultra_longue_et_unique"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Durée de validité du token (30 minutes)

# Création de l'application FastAPI
app = FastAPI()

# Initialisation de la sécurité HTTP Basic
security = HTTPBasic()

# Configuration de la connexion à MySQL
DB_HOST = "10.19.4.2"
DB_PORT = 3306
DB_USER = "root"  # Remplacez par l'utilisateur MySQL approprié
DB_PASSWORD = "my-secret-pw"  # Mot de passe MySQL
DB_NAME = "Projeti5"

# Fonction utilitaire pour obtenir une connexion MySQL
async def get_db_connection():
    return await aiomysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        db=DB_NAME,
    )
# Fonction pour vérifier l'authentification via MySQL


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)  # Par défaut 15 minutes
    to_encode.update({"exp": expire})  # Ajout de la date d'expiration
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            # Requête SQL pour vérifier l'utilisateur
            query = "SELECT COUNT(*) FROM users WHERE email = %s AND password_hash = %s"
            await cursor.execute(query, (credentials.username, credentials.password))
            result = await cursor.fetchone()

            if result[0] == 0:
                raise HTTPException(
                    status_code=401,
                    detail="Nom d'utilisateur ou mot de passe incorrect",
                )
    finally:
        conn.close()

    return credentials.username
# Fonction pour récupérer les données utilisateur et activité
async def get_user_data(user_email: str):
    conn = await get_db_connection()
    try:
        async with conn.cursor(aiomysql.DictCursor) as cursor:
            # Récupérer les informations de base de l'utilisateur
            query_user = "SELECT * FROM users WHERE email = %s"
            await cursor.execute(query_user, (user_email,))
            user_info = await cursor.fetchone()

            if not user_info:
                raise HTTPException(status_code=404, detail="Utilisateur non trouvé.")

            # Récupérer les dernières données d'activité de l'utilisateur
            query_activity = """
                SELECT * 
                FROM activity_tracking 
                WHERE user_id = %s 
                ORDER BY date_time DESC LIMIT 1
            """
            await cursor.execute(query_activity, (user_info["user_id"],))
            activity_info = await cursor.fetchone()

            return {
                "user": user_info,
                "activity": activity_info or {},  # Par défaut, un dictionnaire vide si pas d'activité
            }
    finally:
        conn.close()

async def generate_sport_program(user_email: str):
    # Récupérer les données utilisateur et activité
    user_data = await get_user_data(user_email)

    # Construire le texte personnalisé pour l'API
    user = user_data["user"]
    activity = user_data["activity"]

    # Exemples de variables récupérées
    first_name = user["first_name"]
    last_name = user["last_name"]
    gender = user["gender"]
    heart_rate = activity.get("heart_rate", "non spécifié")
    steps = activity.get("steps", "non spécifié")
    calories = activity.get("calories_burned", "non spécifié")

    # Texte personnalisé pour l'IA
    text = (
        f"Créer un programme sportif très très court pour {first_name} {last_name}, un(e) {gender.lower()} "
        f"Lors de sa dernière activité, la fréquence cardiaque était de {heart_rate}, "
        f"il/elle a fait {steps} pas et brûlé {calories} calories. Fait moi le programme Sans saut de ligne, Sans titre, Sans gras sans \n juste tu me sépara chaque exercice par $ et quelques espaces"
    )

    # Préparer la requête pour l'API externe
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=AIzaSyBVew6C8PD2Umm6sOQE826XNgbJtQwHqu0"
    payload = {
        "contents": [{"parts": [{"text": text}]}]
    }
    headers = {"Content-Type": "application/json"}

    # Envoyer la requête HTTP
    timeout = httpx.Timeout(30.0)
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
        response = await client.post(url, json=payload, headers=headers)

          # Expression régulière pour extraire la partie après "text": " et jusqu'à la fin de la chaîne
        match = re.search(r'"text":\s*"([^"]+)"', response.content.decode("utf-8"))

        # Si une correspondance est trouvée, on l'affiche
        if match:
            text_content = match.group(1)
            print(text_content)
            return(text_content)
        else:
            print("Texte non trouvé.")
        return response.content.decode("utf-8")

async def generate_sport_conseils(user_email: str, Exercice :str):
    # Récupérer les données utilisateur et activité
    user_data = await get_user_data(user_email)

    # Construire le texte personnalisé pour l'API
    user = user_data["user"]
    activity = user_data["activity"]

    # Exemples de variables récupérées
    first_name = user["first_name"]
    last_name = user["last_name"]
    gender = user["gender"]
    heart_rate = activity.get("heart_rate", "non spécifié")
    steps = activity.get("steps", "non spécifié")
    calories = activity.get("calories_burned", "non spécifié")

    # Texte personnalisé pour l'IA
    text = (
    f"Donne un conseil en tant que coach sportif pour l'exercice {Exercice} à {first_name} {last_name}, un(e) {gender.lower()}. "
    f"Lors de sa dernière activité, la fréquence cardiaque était de {heart_rate}, il/elle a fait {steps} pas et brûlé {calories} calories. "
    f"Le conseil doit être direct et pratique, sans détails superflus. Sépare chaque conseil avec un signe '$' et évite les sauts de ligne."
    f"Précise également la posture où comment réaliser l'exercice."
    f"rajoute moi un petit mot d'encouragement à la fin"
)


    # Préparer la requête pour l'API externe
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=AIzaSyBVew6C8PD2Umm6sOQE826XNgbJtQwHqu0"
    payload = {
        "contents": [{"parts": [{"text": text}]}]
    }
    headers = {"Content-Type": "application/json"}

    # Envoyer la requête HTTP
    timeout = httpx.Timeout(30.0)
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
        response = await client.post(url, json=payload, headers=headers)

          # Expression régulière pour extraire la partie après "text": " et jusqu'à la fin de la chaîne
        match = re.search(r'"text":\s*"([^"]+)"', response.content.decode("utf-8"))

        # Si une correspondance est trouvée, on l'affiche
        if match:
            text_content = match.group(1)
            print(text_content)
            return(text_content)
        else:
            print("Texte non trouvé.")
        return response.content.decode("utf-8")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")  # Endpoint où récupérer un token

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401, detail="Impossible de valider le token JWT."
            )
        return username  # Retourne l'email de l'utilisateur
    except JWTError:
        raise HTTPException(
            status_code=401, detail="Token JWT invalide ou expiré."
        )

# Définition d'un point d'entrée GET
@app.get("/")
def read_root():
    return JSONResponse(content={"message": "Bonjour, bienvenue sur mon API FastAPI !"})

@app.post("/ProgrammePerso")
async def create_programme_perso(current_user: str = Depends(get_current_user)):
    # Utiliser l'email de l'utilisateur pour générer le programme
    generated_program = await generate_sport_program(current_user)

    # Récupérer l'ID de l'utilisateur à partir de l'email
    user_id = await get_user_id_by_email(current_user)

    # Connexion à la base de données pour enregistrer le programme
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            # Insérer le programme généré dans la table 'user_programs'
            query_insert = """
                INSERT INTO user_programs (user_id, program, created_at)
                VALUES (%s, %s, NOW())
            """
            await cursor.execute(query_insert, (user_id, generated_program))
            await conn.commit()

        # Exemple de réponse
        response = {
            "message": "Programme généré et enregistré avec succès !",
            "programme": generated_program,
            "utilisateur": current_user,
        }
        return JSONResponse(content=response)

    finally:
        conn.close()


class ExerciceModel(BaseModel):
    exercice: str

@app.post("/ConseilsExos")
async def create_programme_perso(current_user: str = Depends(get_current_user), exercice: ExerciceModel = ""):
    # Vérification de l'authentification via Basic Auth
    username = current_user  # Email de l'utilisateur authentifié

    # Générer les conseils basés sur l'exercice reçu
    generated_conseils = await generate_sport_conseils(username, exercice)

    # Exemple de réponse
    response = {
        "message": "Conseils générés avec succès !",
        "conseils": generated_conseils,
        "utilisateur": username,
    }
    return JSONResponse(content=response)

# Modèle pour la création d'un utilisateur
class CreateUserRequest(BaseModel):
    email: EmailStr
    password_hash: str
    date_of_birth: str

# Définition d'un point d'entrée POST pour créer un utilisateur
@app.post("/create_user")
async def create_user(user: CreateUserRequest):
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            # Vérifier si l'utilisateur existe déjà
            query_check = "SELECT COUNT(*) FROM users WHERE email = %s"
            await cursor.execute(query_check, (user.email,))
            result = await cursor.fetchone()

            if result[0] > 0:
                raise HTTPException(status_code=400, detail="Un utilisateur avec cet email existe déjà.")

            # Insérer un nouvel utilisateur dans la base de données
            query_insert = "INSERT INTO users (email, password_hash, date_of_birth) VALUES (%s, %s, %s)"
            await cursor.execute(query_insert, (user.email, user.password_hash, user.date_of_birth))
            await conn.commit()

        return JSONResponse(content={"message": "Utilisateur créé avec succès !", "email": user.email})
    finally:
        conn.close()


class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/login")
async def login(credentials: HTTPBasicCredentials = Depends(security)):
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            # Vérification des identifiants dans la base de données
            query_check = "SELECT user_id FROM users WHERE email = %s AND password_hash = %s"
            await cursor.execute(query_check, (credentials.username, credentials.password))
            user = await cursor.fetchone()

            if not user:
                raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect.")
            
            user_id = user[0]

            # Génération du token JWT
            access_token = create_access_token(
                data={"sub": credentials.username},  # Le "subject" est l'email
                expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            )
            return JSONResponse(
                content={
                    "access_token": access_token,
                    "token_type": "bearer",
                    "message": "Connexion réussie",
                }
            )

    finally:
        conn.close()

@app.post("/recent_activity")
async def recent_activity(current_user: str = Depends(get_current_user)):
    conn = await get_db_connection()  # Connexion à la base de données
    try:
        async with conn.cursor() as cursor:
            # Vérifier si l'utilisateur existe avec ses identifiants
            query_user = "SELECT user_id FROM users WHERE email = %s"
            await cursor.execute(query_user, (current_user))
            user = await cursor.fetchone()

            if not user:
                raise HTTPException(status_code=401, detail="Identifiants invalides.")

            user_id = user[0]

            # Récupérer l'activité la plus récente pour cet utilisateur
            query_activity = """
                SELECT tracking_id, date_time, heart_rate, steps, distance_km, calories_burned
                FROM activity_tracking
                WHERE user_id = %s
                ORDER BY date_time DESC
                LIMIT 1
            """
            await cursor.execute(query_activity, (user_id,))
            activity = await cursor.fetchone()

            if not activity:
                raise HTTPException(status_code=404, detail="Aucune activité trouvée pour cet utilisateur.")

            # Convertir datetime en format ISO 8601
            activity_data = {
                "tracking_id": activity[0],
                "date_time": activity[1].isoformat(),  # Conversion de datetime en chaîne
                "heart_rate": activity[2],
                "steps": activity[3],
                "distance_km": float(activity[4]),
                "calories_burned": float(activity[5])
            }

            return JSONResponse(content={"message": "Activité récupérée avec succès.", "activity": activity_data})

    finally:
        conn.close()


# Fonction pour récupérer l'user_id en fonction du username (email)
async def get_user_id_by_email(username: str):
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            # Requête SQL pour récupérer l'user_id à partir de l'email
            query = "SELECT user_id FROM users WHERE email = %s"
            await cursor.execute(query, (username,))
            result = await cursor.fetchone()

            if result is None:
                raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
            
            return result[0]  # Retourne l'user_id

    finally:
        conn.close()

# Fonction pour récupérer les exercices de l'utilisateur
async def get_user_exercises(user_id: int):
    conn = await get_db_connection()  # Connexion à la base de données
    try:
        async with conn.cursor() as cursor:
            # Requête pour récupérer les exercices de l'utilisateur
            query = """
                SELECT e.exercise_id, e.name, e.description, e.difficulty, e.muscle_group, ue.created_at
                FROM user_exercises ue
                JOIN exercises e ON ue.exercise_id = e.exercise_id
                WHERE ue.user_id = %s
                ORDER BY ue.created_at DESC;
            """
            await cursor.execute(query, (user_id,))  # Exécution de la requête
            exercises = await cursor.fetchall()  # Récupération des résultats

            # Formater la réponse pour chaque exercice
            exercise_list = []
            for row in exercises:
                exercise_data = {
                    "exercise_id": row[0],
                    "name": row[1],
                    "description": row[2],
                    "difficulty": row[3],
                    "muscle_group": row[4],
                    "created_at": row[5].strftime("%Y-%m-%d %H:%M:%S")  # Formatage de la date
                }
                exercise_list.append(exercise_data)

            return exercise_list  # Retourne la liste des exercices enregistrés
    finally:
        conn.close()

# Point d'entrée pour récupérer les exercices de l'utilisateur
@app.get("/user/exercises")
async def get_exercises(current_user: str = Depends(get_current_user)):
    # Récupérer le username via l'authentification
    username = current_user

    # Récupérer l'user_id à partir du username
    user_id = await get_user_id_by_email(username)

    # Récupérer les exercices enregistrés pour l'utilisateur
    exercises = await get_user_exercises(user_id)

    # Retourner les exercices en réponse JSON
    return JSONResponse(content={"message": "Exercices récupérés avec succès", "exercises": exercises})

# Point d'entrée pour récupérer les exercices
@app.get("/exercises")
async def get_exercises(muscle_group: str = Query(None, description="Filtrer par groupe musculaire (ex: 'Upper Body')")):
    conn = await get_db_connection()  # Connexion à la base de données
    try:
        async with conn.cursor() as cursor:
            # Construire la requête SQL
            if muscle_group:
                query = "SELECT exercise_id, name, description, difficulty, muscle_group, image_url FROM exercises WHERE muscle_group = %s"
                await cursor.execute(query, (muscle_group,))
            else:
                query = "SELECT exercise_id, name, description, difficulty, muscle_group, image_url FROM exercises"
                await cursor.execute(query)

            # Récupérer tous les résultats
            results = await cursor.fetchall()
            
            # Vérifier si des exercices ont été trouvés
            if not results:
                raise HTTPException(status_code=404, detail="Aucun exercice trouvé.")

            # Structurer les résultats dans une liste de dictionnaires
            exercises = [
                {
                    "exercise_id": row[0],
                    "name": row[1],
                    "description": row[2],
                    "difficulty": row[3],
                    "muscle_group": row[4],
                    "image": row[5],
                }
                for row in results
            ]

            # Retourner les exercices en réponse JSON
            return JSONResponse(content={"message": "Exercices récupérés avec succès", "exercises": exercises})

    finally:
        conn.close()


class ExerciseRequest(BaseModel):
    exercise_name: str

@app.post("/user/exercises/add")
async def add_exercise_to_user(
    current_user: str = Depends(get_current_user),
    exercise_request: ExerciseRequest = Body(...),
):
    # Récupérer l'user_id en fonction de l'email (current_user)
    user_id = await get_user_id_by_email(current_user)

    # Récupérer l'exercice depuis la table 'exercises' par son nom
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            # Chercher l'exercice dans la base de données par son nom
            query = "SELECT exercise_id FROM exercises WHERE name = %s"
            await cursor.execute(query, (exercise_request.exercise_name,))
            result = await cursor.fetchone()

            if not result:
                raise HTTPException(
                    status_code=404, detail=f"Exercice '{exercise_request.exercise_name}' non trouvé."
                )

            exercise_id = result[0]

            # Ajouter l'exercice à l'utilisateur dans la table 'user_exercises'
            query_insert = "INSERT INTO user_exercises (user_id, exercise_id, created_at) VALUES (%s, %s, NOW())"
            await cursor.execute(query_insert, (user_id, exercise_id))
            await conn.commit()

            return JSONResponse(content={
                "message": f"L'exercice '{exercise_request.exercise_name}' a été ajouté avec succès pour l'utilisateur."
            })

    finally:
        conn.close()

@app.get("/ProgrammesPerso")
async def get_all_programmes(current_user: str = Depends(get_current_user)):
    conn = await get_db_connection()
    
    try:
        async with conn.cursor() as cursor:
            # 1. Récupérer l'ID de l'utilisateur à partir de son email
            query_get_user_id = "SELECT user_id FROM users WHERE email = %s"
            await cursor.execute(query_get_user_id, (current_user,))
            user_id_result = await cursor.fetchone()

            if not user_id_result:
                raise HTTPException(status_code=404, detail="Utilisateur non trouvé.")

            user_id = user_id_result[0]

            # 2. Récupérer les programmes associés à cet utilisateur par `user_id`
            query_select = """
                SELECT user_program_id, user_id, program, created_at 
                FROM user_programs 
                WHERE user_id = %s
            """
            await cursor.execute(query_select, (user_id,))
            programmes = await cursor.fetchall()

        if not programmes:
            raise HTTPException(status_code=404, detail="Aucun programme trouvé pour cet utilisateur.")

        # Formater la réponse avec les programmes récupérés
        response = {
            "message": "Tous les programmes récupérés avec succès",
            "programmes": [
                {
                    "id": programme[0],
                    "user_id": programme[1],
                    "program": programme[2],
                    "created_at": programme[3].strftime("%Y-%m-%d %H:%M:%S")  # Format de la date
                } for programme in programmes
            ]
        }
        return JSONResponse(content=response)

    finally:
        conn.close()


        

# Exécution de l'application si ce fichier est exécuté directement
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)



