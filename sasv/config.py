"""Configuration centrale du SASV."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
SECURE_DIR = BASE_DIR / "secure"
INGEST_DIR = SECURE_DIR / "ingested"

BASE_CSV = DATA_DIR / "ventes_agences.csv"
USERS_FILE = SECURE_DIR / "users.json"
AUDIT_FILE = SECURE_DIR / "audit_log.jsonl"
AUDIT_KEY_FILE = SECURE_DIR / ".audit_key"
RULES_FILE = SECURE_DIR / "alert_rules.json"
OUTBOX_FILE = SECURE_DIR / "outbox.jsonl"
INGEST_REGISTRY = SECURE_DIR / "ingest_registry.json"

for d in (SECURE_DIR, INGEST_DIR):
    d.mkdir(parents=True, exist_ok=True)

# Mode démonstration : affiche les codes MFA à l'écran de connexion.
# À DÉSACTIVER EN PRODUCTION :  SASV_DEMO=0 streamlit run app.py
DEMO_MODE = os.getenv("SASV_DEMO", "1") == "1"

SESSION_TIMEOUT_MIN = int(os.getenv("SASV_SESSION_TIMEOUT", "15"))
MAX_FAILED_LOGINS = 5
LOCKOUT_MIN = 15
AUDIT_RETENTION_YEARS = 5

APP_NAME = "SASV"
APP_FULL_NAME = "Système Automatisé et Sécurisé de Suivi des Ventes"

# Palette (dérivée de la maquette, validée daltonisme)
PURPLE = "#7A3E9D"
RED = "#D62E3F"
ORANGE = "#E8963A"
CORAL = "#F26B6B"
INK = "#1A1A1A"
MUTED = "#6B6B6B"
GRID = "#ECECEC"

CANAL_COLORS = {"Agence": PURPLE, "POS": RED, "E-commerce": ORANGE}

AUDIT_GRANT_HOURS = [1, 4, 24]   # durées proposées pour un accès temporaire au journal d'audit

# "audit_on_request" : le rôle n'accède au journal d'audit que sur autorisation temporaire
# accordée par le Responsable sécurité (séparation des pouvoirs).
ROLES = {
    "direction": {
        "label": "Direction Générale",
        "pages": ["accueil", "dashboard", "alertes", "rapports", "compte", "aide"],
        "audit_on_request": True,
    },
    "manager": {
        "label": "Manager régional",
        "pages": ["accueil", "dashboard", "alertes", "rapports", "compte", "aide"],
    },
    "analyste": {
        "label": "Analyste commercial",
        "pages": ["accueil", "dashboard", "rapports", "compte", "aide"],
    },
    "chef_agence": {
        "label": "Chef d'agence",
        "pages": ["accueil", "dashboard", "alertes", "rapports", "import", "compte", "aide"],
    },
    "agence": {
        "label": "Agent de saisie agence",
        "pages": ["accueil", "import", "compte", "aide"],
    },
    "auditeur": {
        "label": "Responsable sécurité / Auditeur",
        "pages": ["accueil", "audit", "compte", "aide"],
    },
    "admin": {
        "label": "Administrateur des accès",
        "pages": ["accueil", "admin", "compte", "aide"],
    },
}
