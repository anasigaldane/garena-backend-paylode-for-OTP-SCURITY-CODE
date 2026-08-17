import os
import json
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

db = None

def _get_credentials_from_env():
    """Build service account credentials from environment variables."""
    private_key = os.environ.get("FIREBASE_PRIVATE_KEY", "")
    # Fix escaped newlines if they come from env var
    private_key = private_key.replace("\\n", "\n")

    account_info = {
        "type": os.environ.get("FIREBASE_TYPE", "service_account"),
        "project_id": os.environ.get("FIREBASE_PROJECT_ID", ""),
        "private_key_id": os.environ.get("FIREBASE_PRIVATE_KEY_ID", ""),
        "private_key": private_key,
        "client_email": os.environ.get("FIREBASE_CLIENT_EMAIL", ""),
        "client_id": os.environ.get("FIREBASE_CLIENT_ID", ""),
        "auth_uri": os.environ.get("FIREBASE_AUTH_URI", "https://accounts.google.com/o/oauth2/auth"),
        "token_uri": os.environ.get("FIREBASE_TOKEN_URI", "https://oauth2.googleapis.com/token"),
        "auth_provider_x509_cert_url": os.environ.get("FIREBASE_AUTH_PROVIDER_X509_CERT_URL", "https://www.googleapis.com/oauth2/v1/certs"),
        "client_x509_cert_url": os.environ.get("FIREBASE_CLIENT_X509_CERT_URL", ""),
        "universe_domain": os.environ.get("FIREBASE_UNIVERSE_DOMAIN", "googleapis.com"),
    }

    # Validate required fields
    required = ["project_id", "private_key", "client_email"]
    missing = [k for k in required if not account_info.get(k)]
    if missing:
        print(f"[Firebase] Missing env vars: {missing}")
        return None
    return credentials.Certificate(account_info)

try:
    # Option 1: File-based service account
    service_account_path = os.environ.get("FIREBASE_SERVICE_ACCOUNT_PATH", "firebase/serviceAccount.json")
    if os.path.exists(service_account_path):
        cred = credentials.Certificate(service_account_path)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("[Firebase] Connected via serviceAccount.json file")
    else:
        # Option 2: Environment variables
        cred = _get_credentials_from_env()
        if cred:
            firebase_admin.initialize_app(cred)
            db = firestore.client()
            print("[Firebase] Connected via environment variables")
        else:
            print("[Firebase] No credentials found. Set either:")
            print("  - FIREBASE_SERVICE_ACCOUNT_PATH pointing to a JSON file, OR")
            print("  - FIREBASE_PROJECT_ID, FIREBASE_PRIVATE_KEY, FIREBASE_CLIENT_EMAIL env vars")
except Exception as e:
    print(f"[Firebase] Initialization failed: {e}")
    db = None
