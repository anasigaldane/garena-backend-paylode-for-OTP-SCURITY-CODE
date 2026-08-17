import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
import os

# Chemin vers la clé service account (configurable via env)
service_account_path = os.environ.get(
    "FIREBASE_SERVICE_ACCOUNT_PATH", 
    "firebase/serviceAccount.json"
)

cred = credentials.Certificate(service_account_path)
firebase_admin.initialize_app(cred)
db = firestore.client()
