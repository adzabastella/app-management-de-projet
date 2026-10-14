"""E1 Collecte, validation et consolidation des ventes (3 canaux)."""
import hashlib
import io
import json
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from .config import BASE_CSV, INGEST_DIR, INGEST_REGISTRY

COLUMNS = ["ref", "jour", "canal", "region", "ville", "point_vente", "vendeur", "produit",
           "famille", "qte", "prix_unit", "remise_pct", "montant", "devise"]
CANAUX = ["POS", "Agence", "E-commerce"]
REGIONS = ["Adamaoua", "Centre", "Est", "Extreme-Nord", "Littoral", "Nord", "Nord-Ouest",
           "Ouest", "Sud", "Sud-Ouest"]
FAMILLES = ["Agricole", "Alimentaire", "Boissons", "Cosmetique", "Equipement", "Textile"]
JOURS_FR = ["Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi", "Dimanche"]
MOIS_FR = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."]


def _sources_signature() -> tuple:
    files = [BASE_CSV] + sorted(INGEST_DIR.glob("*.csv"))
    return tuple((str(f), f.stat().st_mtime) for f in files)


def _read(path_or_buf) -> pd.DataFrame:
    return pd.read_csv(path_or_buf, sep=None, engine="python", encoding="utf-8-sig")


@st.cache_data(show_spinner="Consolidation des flux de ventes…")
def _load(signature: tuple) -> pd.DataFrame:
    frames = []
    for path, _ in signature:
        df = _read(path)
        df["source"] = "Historique" if path == str(BASE_CSV) else "Import " + Path(path).stem
        frames.append(df)
    df = pd.concat(frames, ignore_index=True).drop_duplicates("ref", keep="first")
    df["jour"] = pd.to_datetime(df["jour"])
    df["mois"] = df["jour"].dt.to_period("M").dt.to_timestamp()
    df["semaine"] = df["jour"].dt.to_period("W").dt.start_time
    df["jour_sem"] = df["jour"].dt.dayofweek
    df["remise_fcfa"] = (df["qte"] * df["prix_unit"] - df["montant"]).clip(lower=0)
    for c in ("canal", "region", "ville", "point_vente", "vendeur", "produit", "famille"):
        df[c] = df[c].astype("category")
    return df


def load_sales() -> pd.DataFrame:
    return _load(_sources_signature())


def last_update() -> datetime:
    return datetime.fromtimestamp(max(m for _, m in _sources_signature()))


def apply_perimeter(df: pd.DataFrame, user: dict) -> pd.DataFrame:
    """US-204 — habilitations par périmètre géographique et famille de produits."""
    if user.get("regions"):
        df = df[df["region"].isin(user["regions"])]
    if user.get("familles"):
        df = df[df["famille"].isin(user["familles"])]
    return df


def fmt_fcfa(x: float, short: bool = True) -> str:
    if pd.isna(x):
        return "—"
    if short:
        for div, suf in ((1e9, " Md"), (1e6, " M"), (1e3, " k")):
            if abs(x) >= div:
                return f"{x / div:,.1f}{suf} FCFA".replace(",", " ").replace(".", ",")
    return f"{x:,.0f} FCFA".replace(",", " ")


def fmt_int(x) -> str:
    return f"{x:,.0f}".replace(",", " ")


def fmt_date(d) -> str:
    d = pd.Timestamp(d)
    return f"{d.day} {MOIS_FR[d.month - 1]} {d.year}"


# --------------------------------------------------------------------------- import

def _registry() -> dict:
    if INGEST_REGISTRY.exists():
        return json.loads(INGEST_REGISTRY.read_text(encoding="utf-8"))
    return {}


def validate_upload(raw: bytes, existing_refs: set):
    """US-103 — contrôle d'un dépôt d'agence. Retourne (df_valide, df_rejets, rapport)."""
    sha = hashlib.sha256(raw).hexdigest()
    report = {"sha256": sha, "errors": []}
    if sha in _registry():
        report["errors"].append(f"Fichier déjà déposé le {_registry()[sha]['ts']} (empreinte SHA-256 identique).")
        return None, None, report
    try:
        df = _read(io.BytesIO(raw))
    except Exception as exc:  # noqa: BLE001
        report["errors"].append(f"Fichier illisible : {exc}")
        return None, None, report
    df.columns = [c.strip().lower() for c in df.columns]
    missing = [c for c in COLUMNS if c not in df.columns]
    if missing:
        report["errors"].append("Colonnes manquantes : " + ", ".join(missing))
        return None, None, report
    df = df[COLUMNS].copy()
    reasons = pd.Series("", index=df.index)

    def flag(mask, msg):
        reasons.loc[mask & (reasons == "")] = msg

    dates = pd.to_datetime(df["jour"], errors="coerce", format="%Y-%m-%d")
    flag(dates.isna(), "Date invalide (AAAA-MM-JJ attendu)")
    flag(dates > pd.Timestamp.now(), "Date dans le futur")
    for c in ("qte", "prix_unit", "remise_pct", "montant"):
        df[c] = pd.to_numeric(df[c], errors="coerce")
        flag(df[c].isna(), f"{c} non numérique")
    flag(df["qte"] <= 0, "Quantité ≤ 0")
    flag(df["prix_unit"] <= 0, "Prix unitaire ≤ 0")
    flag((df["remise_pct"] < 0) | (df["remise_pct"] > 50), "Remise hors bornes (0-50 %)")
    theo = df["qte"] * df["prix_unit"] * (1 - df["remise_pct"] / 100)
    flag((theo - df["montant"]).abs() > 1, "Montant incohérent (qte × prix × (1 − remise))")
    flag(~df["canal"].isin(CANAUX), "Canal inconnu")
    flag(~df["region"].isin(REGIONS), "Région inconnue")
    flag(~df["famille"].isin(FAMILLES), "Famille inconnue")
    flag(df["devise"] != "FCFA", "Devise non FCFA")
    flag(df["ref"].duplicated(keep="first"), "Référence en double dans le fichier")
    flag(df["ref"].isin(existing_refs), "Référence déjà enregistrée")

    rejected = df[reasons != ""].assign(motif=reasons[reasons != ""])
    valid = df[reasons == ""].copy()
    valid["jour"] = dates[reasons == ""].dt.strftime("%Y-%m-%d")
    report.update(total=len(df), valid=len(valid), rejected=len(rejected))
    return valid, rejected, report


def commit_upload(valid: pd.DataFrame, report: dict, user: str, filename: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = INGEST_DIR / f"{stamp}_{user}.csv"
    n = 1
    while path.exists():  # deux dépôts dans la même seconde ne doivent pas s'écraser
        n += 1
        path = INGEST_DIR / f"{stamp}_{user}_{n}.csv"
    valid.to_csv(path, sep=";", index=False)
    reg = _registry()
    reg[report["sha256"]] = {"ts": datetime.now().isoformat(timespec="seconds"), "user": user,
                             "file": filename, "stored": path.name, "rows": int(report["valid"])}
    INGEST_REGISTRY.write_text(json.dumps(reg, indent=2, ensure_ascii=False), encoding="utf-8")
    st.cache_data.clear()
    return path.name


def ingest_history() -> pd.DataFrame:
    reg = _registry()
    if not reg:
        return pd.DataFrame(columns=["ts", "user", "file", "rows", "sha256"])
    return (pd.DataFrame([{**v, "sha256": k[:16] + "…"} for k, v in reg.items()])
            .sort_values("ts", ascending=False))
