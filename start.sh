#!/bin/bash
# Commande de démarrage recommandée pour le cloud
# Render, Railway, Koyeb, Heroku etc.

# Option A: Gunicorn avec workers Uvicorn (production)
gunicorn -w 2 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:${PORT:-8000}

# Option B: Uvicorn seul (développement / petit trafic)
# uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
