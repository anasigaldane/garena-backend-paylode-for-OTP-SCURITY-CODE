import os
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

db = None

try:
    service_account_path = os.environ.get(
        "FIREBASE_SERVICE_ACCOUNT_PATH",
        "firebase/serviceAccount.json"
    )
    if os.path.exists(service_account_path):
        cred = credentials.Certificate(service_account_path)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
    else:
        print(f"[Firebase] Service account not found at {service_account_path}")
except Exception as e:
    print(f"[Firebase] Initialization failed: {e}")
    db = None
