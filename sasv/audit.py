"""E5 Journalisation infalsifiable.

Chaque entrée est chaînée à la précédente par un HMAC-SHA256 :
    hash_n = HMAC(clé, hash_{n-1} || contenu_n)
Toute modification, suppression ou insertion d'une ligne casse la chaîne,
ce que `verify_chain()` détecte et localise.
"""
import hashlib
import hmac
import json
import os
import secrets
import threading
from datetime import datetime, timedelta

import pandas as pd

from .config import AUDIT_FILE, AUDIT_KEY_FILE, AUDIT_RETENTION_YEARS

_LOCK = threading.Lock()
GENESIS = "0" * 64


def _key() -> bytes:
    env = os.getenv("SASV_AUDIT_KEY")
    if env:
        return env.encode()
    if not AUDIT_KEY_FILE.exists():
        AUDIT_KEY_FILE.write_text(secrets.token_hex(32))
        try:
            os.chmod(AUDIT_KEY_FILE, 0o600)
        except OSError:
            pass
    return AUDIT_KEY_FILE.read_text().strip().encode()


def _payload(e: dict) -> str:
    core = {k: e[k] for k in ("seq", "ts", "user", "role", "action", "detail", "status", "prev")}
    return json.dumps(core, sort_keys=True, ensure_ascii=False)


def _sign(e: dict) -> str:
    return hmac.new(_key(), _payload(e).encode(), hashlib.sha256).hexdigest()


def _last_entry():
    if not AUDIT_FILE.exists():
        return None
    with AUDIT_FILE.open("rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        chunk = 4096
        while True:
            # Lit la fin du fichier par blocs croissants jusqu'à obtenir une dernière ligne complète.
            f.seek(max(0, size - chunk))
            tail = f.read().rstrip(b"\r\n")
            if not tail:
                return None
            if b"\n" in tail or chunk >= size:
                return json.loads(tail.rsplit(b"\n", 1)[-1].decode("utf-8"))
            chunk *= 4


def log(user: str, role: str, action: str, detail: str = "", status: str = "OK") -> None:
    with _LOCK:
        last = _last_entry()
        entry = {
            "seq": (last["seq"] + 1) if last else 1,
            "ts": datetime.now().isoformat(timespec="seconds"),
            "user": user or "anonyme",
            "role": role or "-",
            "action": action,
            "detail": detail,
            "status": status,
            "prev": last["hash"] if last else GENESIS,
        }
        entry["hash"] = _sign(entry)
        with AUDIT_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


AUDIT_COLUMNS = ["seq", "ts", "user", "role", "action", "detail", "status", "prev", "hash"]


def read_all() -> pd.DataFrame:
    rows = []
    if AUDIT_FILE.exists():
        for l in AUDIT_FILE.read_text(encoding="utf-8").splitlines():
            if l.strip():
                try:
                    rows.append(json.loads(l))
                except json.JSONDecodeError:
                    continue  # ligne altérée : signalée par verify_chain()
    if not rows:
        return pd.DataFrame({c: pd.Series(dtype="datetime64[ns]" if c == "ts" else object) for c in AUDIT_COLUMNS})
    df = pd.DataFrame(rows)
    df["ts"] = pd.to_datetime(df["ts"])
    return df


def verify_chain():
    """Retourne (ok, nb_entrees, seq_rompue_ou_None, message)."""
    if not AUDIT_FILE.exists():
        return True, 0, None, "Journal vide."
    prev = GENESIS
    n = 0
    for i, line in enumerate(AUDIT_FILE.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            return False, n, i, f"Ligne {i} illisible (format altéré)."
        if e.get("prev") != prev:
            return False, n, e.get("seq", i), f"Chaînage rompu à l'entrée n°{e.get('seq', i)} (entrée supprimée ou insérée)."
        if not hmac.compare_digest(e.get("hash", ""), _sign(e)):
            return False, n, e.get("seq", i), f"Signature invalide à l'entrée n°{e.get('seq', i)} (contenu modifié)."
        prev = e["hash"]
        n += 1
    return True, n, None, f"{n} entrées vérifiées — chaîne intègre."


def retention_status():
    df = read_all()
    limit = datetime.now() - timedelta(days=365 * AUDIT_RETENTION_YEARS)
    if df.empty:
        return 0, limit
    return int((df["ts"] < limit).sum()), limit


def suspicious_activity(df: pd.DataFrame, hours: int = 24, threshold: int = 3) -> pd.DataFrame:
    """US E5 — comportements suspects : échecs de connexion répétés, exports massifs."""
    if df.empty:
        return pd.DataFrame()
    recent = df[df["ts"] >= datetime.now() - timedelta(hours=hours)]
    fails = (recent[recent["action"].isin(["LOGIN", "MFA"]) & (recent["status"] != "OK")]
             .groupby("user").size().rename("echecs_auth"))
    exports = recent[recent["action"].str.startswith("EXPORT")].groupby("user").size().rename("exports")
    out = pd.concat([fails, exports], axis=1).reindex(columns=["echecs_auth", "exports"]).fillna(0).astype(int)
    out = out[(out["echecs_auth"] >= threshold) | (out["exports"] >= 10)]
    out.index.name = "user"
    return out.reset_index()
