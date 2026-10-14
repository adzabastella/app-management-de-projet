"""E4 — Moteur d'alertes sur seuils de KPIs."""
import json
from datetime import datetime

import pandas as pd

from .config import RULES_FILE, OUTBOX_FILE
from .data import fmt_fcfa

DEFAULT_RULES = {
    "baisse_ca_global": {"label": "Baisse du CA global (période vs période précédente)", "seuil": 10.0, "unite": "%", "actif": True},
    "baisse_ca_region": {"label": "Baisse du CA d'une région", "seuil": 15.0, "unite": "%", "actif": True},
    "baisse_point_vente": {"label": "Baisse du CA d'un point de vente", "seuil": 25.0, "unite": "%", "actif": True},
    "remise_moyenne": {"label": "Taux de remise moyen trop élevé", "seuil": 3.0, "unite": "%", "actif": True},
    "objectif_mensuel": {"label": "Mois en cours en retard sur l'objectif (moy. 3 mois)", "seuil": 10.0, "unite": "%", "actif": True},
    "collecte_interrompue": {"label": "Point de vente sans remontée de ventes", "seuil": 3.0, "unite": "jours", "actif": True},
}

SEVERITY = {
    "critique": {"icon": "⛔", "color": "#B42318", "rank": 0},
    "élevée": {"icon": "▲", "color": "#C2410C", "rank": 1},
    "moyenne": {"icon": "●", "color": "#A16207", "rank": 2},
}


def load_rules() -> dict:
    if RULES_FILE.exists():
        try:
            rules = json.loads(RULES_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            rules = {}
        return {k: {**DEFAULT_RULES[k], **rules.get(k, {})} for k in DEFAULT_RULES}
    return json.loads(json.dumps(DEFAULT_RULES))


def save_rules(rules: dict) -> None:
    RULES_FILE.write_text(json.dumps(rules, indent=2, ensure_ascii=False), encoding="utf-8")


def _sev(ecart: float, seuil: float) -> str:
    if ecart >= 2 * seuil:
        return "critique"
    if ecart >= 1.4 * seuil:
        return "élevée"
    return "moyenne"


def evaluate(df: pd.DataFrame, days: int = 30) -> pd.DataFrame:
    """Évalue les règles sur le périmètre de l'utilisateur. Fenêtre glissante de `days` jours."""
    rules = load_rules()
    if df.empty:
        return pd.DataFrame()
    ref = df["jour"].max()
    cur = df[df["jour"] > ref - pd.Timedelta(days=days)]
    prev = df[(df["jour"] <= ref - pd.Timedelta(days=days)) & (df["jour"] > ref - pd.Timedelta(days=2 * days))]
    out = []

    def add(rule, cible, msg, ecart, seuil, valeur):
        out.append({"regle": rule, "cible": cible, "message": msg, "ecart": round(ecart, 1),
                    "severite": _sev(ecart, seuil), "valeur": valeur})

    r = rules["baisse_ca_global"]
    if r["actif"] and prev["montant"].sum() > 0:
        var = (cur["montant"].sum() / prev["montant"].sum() - 1) * 100
        if -var >= r["seuil"]:
            add("baisse_ca_global", "Périmètre complet",
                f"CA des {days} derniers jours en baisse de {-var:.1f} % ({fmt_fcfa(cur['montant'].sum())})",
                -var, r["seuil"], fmt_fcfa(cur["montant"].sum()))

    for key, col in (("baisse_ca_region", "region"), ("baisse_point_vente", "point_vente")):
        r = rules[key]
        if not r["actif"]:
            continue
        p = prev.groupby(col, observed=True)["montant"].sum()
        p = p[p > 0]
        # Une cible sans aucune vente sur la fenêtre courante doit apparaître comme une baisse de 100 %.
        c = cur.groupby(col, observed=True)["montant"].sum().reindex(p.index, fill_value=0)
        var = ((c / p - 1) * 100).dropna()
        for name, v in var[var <= -r["seuil"]].items():
            add(key, str(name), f"CA en baisse de {-v:.1f} % sur {days} jours ({fmt_fcfa(c[name])} vs {fmt_fcfa(p[name])})",
                -v, r["seuil"], fmt_fcfa(c[name]))

    r = rules["remise_moyenne"]
    if r["actif"]:
        brut = (cur["qte"] * cur["prix_unit"]).groupby(cur["point_vente"], observed=True).sum()
        rem = cur.groupby("point_vente", observed=True)["remise_fcfa"].sum()
        taux = (rem / brut * 100).dropna()
        for name, v in taux[taux >= r["seuil"]].items():
            add("remise_moyenne", str(name), f"Taux de remise moyen de {v:.1f} % (seuil {r['seuil']:.0f} %)",
                v - r["seuil"] + r["seuil"] * 0.5, r["seuil"], f"{v:.1f} %")

    r = rules["objectif_mensuel"]
    if r["actif"]:
        month_start = ref.to_period("M").to_timestamp()
        elapsed = (ref - month_start).days + 1
        dim = ref.days_in_month
        last3 = df[(df["mois"] < month_start) & (df["mois"] >= month_start - pd.DateOffset(months=3))]
        n_months = max(last3["mois"].nunique(), 1)
        obj = last3.groupby("region", observed=True)["montant"].sum() / n_months
        obj = obj[obj > 0]
        cur_m = (df[df["mois"] == month_start].groupby("region", observed=True)["montant"].sum()
                 .reindex(obj.index, fill_value=0))
        if elapsed >= 5:
            proj = cur_m / elapsed * dim
            gap = ((1 - proj / obj) * 100).dropna()
            for name, v in gap[gap >= r["seuil"]].items():
                add("objectif_mensuel", str(name),
                    f"Projection fin de mois à {fmt_fcfa(proj[name])}, soit {v:.1f} % sous l'objectif ({fmt_fcfa(obj[name])})",
                    v, r["seuil"], fmt_fcfa(proj[name]))

    r = rules["collecte_interrompue"]
    if r["actif"]:
        last_seen = df.groupby("point_vente", observed=True)["jour"].max()
        gap = (ref - last_seen).dt.days
        for name, v in gap[gap >= r["seuil"]].items():
            add("collecte_interrompue", str(name), f"Aucune vente remontée depuis {v} jours", v, r["seuil"], f"{v} j")

    if not out:
        return pd.DataFrame()
    res = pd.DataFrame(out)
    res["rang"] = res["severite"].map(lambda s: SEVERITY[s]["rank"])
    res["libelle_regle"] = res["regle"].map(lambda k: rules[k]["label"])
    return res.sort_values(["rang", "ecart"], ascending=[True, False]).drop(columns="rang").reset_index(drop=True)


def queue_email(to: str, alerts: pd.DataFrame, user: str) -> None:
    """US-402 — l'envoi SMTP réel se branche ici ; en démo, l'e-mail est placé dans une boîte d'envoi."""
    body = "\n".join(f"[{a.severite.upper()}] {a.cible} — {a.message}" for a in alerts.itertuples())
    with OUTBOX_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": datetime.now().isoformat(timespec="seconds"), "from": "sasv-alertes@entreprise.cm",
                            "to": to, "by": user, "subject": f"[SASV] {len(alerts)} alerte(s) commerciale(s)",
                            "body": body}, ensure_ascii=False) + "\n")


def outbox() -> pd.DataFrame:
    if not OUTBOX_FILE.exists():
        return pd.DataFrame()
    rows = []
    for l in OUTBOX_FILE.read_text(encoding="utf-8").splitlines():
        try:
            rows.append(json.loads(l))
        except json.JSONDecodeError:
            continue
    return pd.DataFrame(rows)
