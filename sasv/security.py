"""E2  Identités, authentification forte (mot de passe + TOTP) et habilitations."""
import json
import re
import threading
from datetime import datetime, timedelta

import bcrypt
import pyotp

from .config import USERS_FILE, MAX_FAILED_LOGINS, LOCKOUT_MIN, ROLES, DEMO_MODE

_LOCK = threading.Lock()

# Comptes de démonstration (mots de passe conformes à la politique)
SEED_USERS = [
    ("dg", "Sasv@Direction2026", "direction", "Direction Générale", [], []),
    ("manager.littoral", "Sasv@Littoral2026", "manager", "Manager Littoral & Sud-Ouest", ["Littoral", "Sud-Ouest"], []),
    ("analyste.alim", "Sasv@Analyse2026", "analyste", "Analyste Alimentaire & Boissons", [], ["Alimentaire", "Boissons"]),
    ("chef.agence.nord", "Sasv@ChefNord2026", "chef_agence", "Chef d'agence Nord", ["Nord", "Extreme-Nord", "Adamaoua"], []),
    ("agence.nord", "Sasv@AgenceNord26", "agence", "Agent de saisie Nord", ["Nord", "Extreme-Nord", "Adamaoua"], []),
    ("auditeur", "Sasv@Audit2026!", "auditeur", "Responsable sécurité", [], []),
    ("admin", "Sasv@Admin2026!", "admin", "Administrateur des accès", [], []),
]

PASSWORD_RULES = [
    (r".{12,}", "au moins 12 caractères"),
    (r"[A-Z]", "une majuscule"),
    (r"[a-z]", "une minuscule"),
    (r"\d", "un chiffre"),
    (r"[^A-Za-z0-9]", "un caractère spécial"),
]


def password_issues(pwd: str) -> list:
    return [msg for rx, msg in PASSWORD_RULES if not re.search(rx, pwd or "")]


def _hash(pwd: str) -> str:
    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt(rounds=12)).decode()


_SEED_LOCK = threading.Lock()
_seed_checked = False


def _load() -> dict:
    global _seed_checked
    if not USERS_FILE.exists() or (DEMO_MODE and not _seed_checked):
        with _SEED_LOCK:  # évite que deux sessions simultanées génèrent deux jeux de secrets différents
            users = json.loads(USERS_FILE.read_text(encoding="utf-8")) if USERS_FILE.exists() else {}
            # Création initiale ; en démonstration, ajoute aussi les comptes de démo absents d'un fichier existant.
            missing = [s for s in SEED_USERS if s[0] not in users] if (DEMO_MODE or not users) else []
            for login, pwd, role, name, regions, familles in missing:
                users[login] = _new_user(pwd, role, name, regions, familles)
            if missing or not USERS_FILE.exists():
                _save(users)
            _seed_checked = True
    return json.loads(USERS_FILE.read_text(encoding="utf-8"))


def _save(users: dict) -> None:
    USERS_FILE.write_text(json.dumps(users, indent=2, ensure_ascii=False), encoding="utf-8")


def _new_user(pwd, role, name, regions, familles):
    return {
        "name": name,
        "role": role,
        "pwd_hash": _hash(pwd),
        "totp_secret": pyotp.random_base32(),
        "regions": regions,
        "familles": familles,
        "active": True,
        "failed": 0,
        "locked_until": None,
        "created": datetime.now().isoformat(timespec="seconds"),
        "last_login": None,
    }


def list_users() -> dict:
    return _load()


def get_user(login: str):
    return _load().get(login)


def check_password(login: str, pwd: str):
    """Retourne (ok, message)."""
    with _LOCK:
        users = _load()
        u = users.get(login)
        if not u:
            bcrypt.checkpw(b"x", _hash("dummy-timing"))  # temps constant approximatif
            return False, "Identifiant ou mot de passe incorrect."
        if not u["active"]:
            return False, "Compte désactivé. Contactez l'administrateur."
        if is_locked(u):
            mins = int((datetime.fromisoformat(u["locked_until"]) - datetime.now()).total_seconds() // 60) + 1
            return False, f"Compte verrouillé suite à des échecs répétés. Réessayez dans {mins} min."
        if bcrypt.checkpw((pwd or "").encode(), u["pwd_hash"].encode()):
            return True, ""
        u["failed"] += 1
        if u["failed"] >= MAX_FAILED_LOGINS:
            u["locked_until"] = (datetime.now() + timedelta(minutes=LOCKOUT_MIN)).isoformat(timespec="seconds")
            u["failed"] = 0
            _save(users)
            return False, f"Trop d'échecs : compte verrouillé {LOCKOUT_MIN} minutes."
        _save(users)
        left = MAX_FAILED_LOGINS - u["failed"]
        return False, f"Identifiant ou mot de passe incorrect ({left} tentative(s) restante(s))."


def is_locked(u: dict) -> bool:
    return bool(u.get("locked_until") and datetime.fromisoformat(u["locked_until"]) > datetime.now())


def check_totp(login: str, code: str) -> bool:
    """Vérifie le code TOTP : compte actif et non verrouillé, code non rejoué, verrouillage après échecs répétés."""
    code = (code or "").strip()
    with _LOCK:
        users = _load()
        u = users.get(login)
        if not u or not u["active"] or is_locked(u):
            return False
        totp = pyotp.TOTP(u["totp_secret"])
        now = datetime.now()
        step = None
        if code.isdigit():
            # Recherche du pas de temps correspondant (fenêtre ±1) pour interdire le rejeu d'un code déjà utilisé.
            for off in (0, -1, 1):
                t = now + timedelta(seconds=off * totp.interval)
                if totp.verify(code, for_time=t):
                    step = totp.timecode(t)
                    break
        ok = step is not None and step > u.get("last_totp_step", -1)
        if ok:
            u["failed"] = 0
            u["last_totp_step"] = step
            u["last_login"] = now.isoformat(timespec="seconds")
        else:
            u["failed"] += 1
            if u["failed"] >= MAX_FAILED_LOGINS:
                u["locked_until"] = (now + timedelta(minutes=LOCKOUT_MIN)).isoformat(timespec="seconds")
                u["failed"] = 0
        _save(users)
    return ok


def current_totp(login: str) -> str:
    return pyotp.TOTP(get_user(login)["totp_secret"]).now()


def provisioning_uri(login: str) -> str:
    return pyotp.TOTP(get_user(login)["totp_secret"]).provisioning_uri(name=login, issuer_name="SASV")


def change_password(login: str, old: str, new: str):
    u = get_user(login)
    if not u or not bcrypt.checkpw((old or "").encode(), u["pwd_hash"].encode()):
        return False, "Mot de passe actuel incorrect."
    issues = password_issues(new)
    if issues:
        return False, "Le nouveau mot de passe doit contenir " + ", ".join(issues) + "."
    if new == old:
        return False, "Le nouveau mot de passe doit être différent de l'actuel."
    with _LOCK:
        users = _load()
        users[login]["pwd_hash"] = _hash(new)
        _save(users)
    return True, "Mot de passe modifié."


def create_user(login, pwd, role, name, regions, familles):
    if not re.fullmatch(r"[a-z0-9._-]{3,32}", login or ""):
        return False, "Identifiant invalide (3-32 caractères : a-z, 0-9, . _ -)."
    if role not in ROLES:
        return False, "Rôle inconnu."
    issues = password_issues(pwd)
    if issues:
        return False, "Le mot de passe doit contenir " + ", ".join(issues) + "."
    with _LOCK:
        users = _load()
        if login in users:
            return False, "Cet identifiant existe déjà."
        users[login] = _new_user(pwd, role, name, regions, familles)
        _save(users)
    return True, f"Utilisateur « {login} » créé."


def set_active(login: str, active: bool):
    with _LOCK:
        users = _load()
        users[login]["active"] = active
        users[login]["locked_until"] = None
        users[login]["failed"] = 0
        _save(users)


def unlock(login: str):
    with _LOCK:
        users = _load()
        users[login]["locked_until"] = None
        users[login]["failed"] = 0
        _save(users)


def reset_mfa(login: str):
    with _LOCK:
        users = _load()
        users[login]["totp_secret"] = pyotp.random_base32()
        users[login].pop("last_totp_step", None)
        _save(users)


def update_perimeter(login, regions, familles):
    with _LOCK:
        users = _load()
        users[login]["regions"] = regions
        users[login]["familles"] = familles
        _save(users)


# --------------------------------------------------------------------------- accès temporaire à l'audit

def has_audit_grant(u: dict) -> bool:
    g = (u or {}).get("audit_access_until")
    return bool(g and datetime.fromisoformat(g) > datetime.now())


def audit_request_status(u: dict) -> str:
    """'accorde', 'en_attente' ou 'aucune'."""
    if has_audit_grant(u):
        return "accorde"
    return "en_attente" if (u or {}).get("audit_request") else "aucune"


def request_audit_access(login: str, motif: str):
    motif = (motif or "").strip()
    if len(motif) < 10:
        return False, "Précisez le motif de la demande (10 caractères minimum)."
    with _LOCK:
        users = _load()
        u = users[login]
        if not ROLES[u["role"]].get("audit_on_request"):
            return False, "Votre rôle ne permet pas de demander cet accès."
        u["audit_request"] = {"ts": datetime.now().isoformat(timespec="seconds"), "motif": motif[:500]}
        _save(users)
    return True, "Demande transmise au Responsable sécurité."


def pending_audit_requests() -> dict:
    return {l: u["audit_request"] for l, u in _load().items() if u.get("audit_request")}


def active_audit_grants() -> dict:
    return {l: u["audit_access_until"] for l, u in _load().items() if has_audit_grant(u)}


def grant_audit_access(login: str, hours: int, by: str) -> str:
    until = (datetime.now() + timedelta(hours=hours)).isoformat(timespec="seconds")
    with _LOCK:
        users = _load()
        users[login]["audit_access_until"] = until
        users[login]["audit_access_by"] = by
        users[login].pop("audit_request", None)
        _save(users)
    return until


def deny_audit_access(login: str):
    with _LOCK:
        users = _load()
        users[login].pop("audit_request", None)
        _save(users)


def revoke_audit_access(login: str):
    with _LOCK:
        users = _load()
        users[login]["audit_access_until"] = None
        _save(users)


def allowed_pages(u: dict) -> list:
    if not u:
        return []
    role = ROLES.get(u["role"], {})
    pages = list(role.get("pages", []))
    if role.get("audit_on_request") and has_audit_grant(u):
        pages.append("audit")
    return pages


def can_access(u: dict, page: str) -> bool:
    return page in allowed_pages(u)
