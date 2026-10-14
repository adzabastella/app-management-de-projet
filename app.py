"""SASV Système Automatisé et Sécurisé de Suivi des Ventes.

Lancement :  streamlit run app.py
"""
import html
import io
import re
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from sasv import alerts as al
from sasv import audit, data, report, security, ui
from sasv.config import (APP_FULL_NAME, AUDIT_GRANT_HOURS, AUDIT_RETENTION_YEARS, CANAL_COLORS, DEMO_MODE,
                         ORANGE, PURPLE, RED, ROLES, RULES_FILE, SESSION_TIMEOUT_MIN)

st.set_page_config(page_title="SASV — Suivi des ventes", page_icon="📊", layout="wide",
                   initial_sidebar_state="expanded")
ui.inject_css()

S = st.session_state
EMAIL_RX = re.compile(r"[^@\s;,]+@[^@\s;,]+\.[A-Za-z]{2,}")
S.setdefault("auth", False)
S.setdefault("step", "password")
S.setdefault("flt", {})


# =============================================================================== session

def who():
    return S.get("login"), S.get("role")


def log(action, detail="", status="OK"):
    audit.log(S.get("login") or S.get("pending_login", "anonyme"), S.get("role", "-"), action, detail, status)


def logout(reason="LOGOUT"):
    log(reason, "Fin de session")
    for k in list(S.keys()):
        del S[k]
    S["auth"] = False
    S["step"] = "password"
    if reason == "SESSION_EXPIREE":
        S["flash"] = f"Session expirée après {SESSION_TIMEOUT_MIN} minutes d'inactivité. Veuillez vous reconnecter."


def session_expired() -> bool:
    last = S.get("last_activity")
    return bool(last and datetime.now() - last > timedelta(minutes=SESSION_TIMEOUT_MIN))


if S.auth:
    if session_expired():
        logout("SESSION_EXPIREE")
        st.rerun()
    _u = security.get_user(S.login)
    if not _u or not _u["active"]:
        logout("SESSION_REVOQUEE")
        S["flash"] = "Votre compte a été désactivé. Contactez l'administrateur."
        st.rerun()
    S["last_activity"] = datetime.now()


def user():
    return security.get_user(S.login)


def can(page: str) -> bool:
    return security.can_access(user(), page)


def perimeter_label(u) -> str:
    parts = []
    parts.append("Régions : " + ", ".join(u["regions"]) if u.get("regions") else "Toutes régions")
    parts.append("Familles : " + ", ".join(u["familles"]) if u.get("familles") else "toutes familles")
    return " · ".join(parts)


def sales():
    return data.apply_perimeter(data.load_sales(), user())


@st.cache_data(show_spinner=False)
def _alerts_cached(sig, regions, familles, days, rules_sig):
    df = data.apply_perimeter(data.load_sales(), {"regions": list(regions), "familles": list(familles)})
    return al.evaluate(df, days)


def current_alerts(days=30):
    u = user()
    rules_sig = RULES_FILE.stat().st_mtime if RULES_FILE.exists() else 0
    return _alerts_cached(data._sources_signature(), tuple(u.get("regions", [])), tuple(u.get("familles", [])), days, rules_sig)


# =============================================================================== connexion

def login_page():
    ui.hero("Connexion sécurisée au SASV", APP_FULL_NAME,
            meta="Authentification forte · mot de passe + code à usage unique (TOTP)")
    if S.get("flash"):
        st.warning(S.pop("flash"))
    _, mid, _ = st.columns([1, 1.25, 1])
    with mid, st.container(key="login-box"):
        if S.step == "password":
            st.markdown("#### Identification")
            with st.form("login", border=False):
                login = st.text_input("Identifiant", autocomplete="username")
                pwd = st.text_input("Mot de passe", type="password", autocomplete="current-password")
                ok = st.form_submit_button("Se connecter", width="stretch")
            if ok:
                login = (login or "").strip().lower()
                good, msg = security.check_password(login, pwd)
                audit.log(login or "anonyme", "-", "LOGIN", "Étape 1 : mot de passe", "OK" if good else "ECHEC")
                if good:
                    S.pending_login = login
                    S.step = "mfa"
                    st.rerun()
                else:
                    st.error(msg)
        else:
            st.markdown("#### Vérification en deux étapes")
            st.caption(f"Saisissez le code à 6 chiffres affiché dans votre application d'authentification "
                       f"pour **{S.pending_login}**.")
            if DEMO_MODE:
                st.info(f"Mode démonstration — code actuel : **{security.current_totp(S.pending_login)}**", icon="🔑")
            with st.form("mfa", border=False):
                code = st.text_input("Code de vérification", max_chars=6, placeholder="123456")
                c1, c2 = st.columns(2)
                ok = c1.form_submit_button("Valider", width="stretch")
                back = c2.form_submit_button("Retour", width="stretch")
            if back:
                S.step = "password"
                st.rerun()
            if ok:
                login = S.pending_login
                if security.check_totp(login, code):
                    u = security.get_user(login)
                    S.update(auth=True, login=login, role=u["role"], name=u["name"],
                             last_activity=datetime.now(), login_time=datetime.now())
                    S.pop("pending_login", None)
                    audit.log(login, u["role"], "MFA", "Étape 2 : code TOTP — session ouverte")
                    st.rerun()
                else:
                    audit.log(login, "-", "MFA", "Code TOTP invalide", "ECHEC")
                    u = security.get_user(login)
                    if u and security.is_locked(u):
                        S.step = "password"
                        S.pop("pending_login", None)
                        S["flash"] = "Trop d'échecs : compte verrouillé. Réessayez plus tard."
                        st.rerun()
                    st.error("Code invalide, expiré ou déjà utilisé.")
        st.markdown("<p class='secure-note'>🔒 Toutes les connexions sont journalisées. "
                    f"Verrouillage après 5 échecs · expiration de session après {SESSION_TIMEOUT_MIN} min d'inactivité.</p>",
                    unsafe_allow_html=True)

    if DEMO_MODE:
        _, mid, _ = st.columns([1, 2.2, 1])
        with mid.expander("Comptes de démonstration"):
            st.dataframe(pd.DataFrame(
                [{"Identifiant": l, "Mot de passe": p, "Rôle": ROLES[r]["label"],
                  "Périmètre": ", ".join(reg or fam) or "Tout"} for l, p, r, _, reg, fam in security.SEED_USERS]),
                hide_index=True, width="stretch")
            st.caption("Désactivez ce mode en production : `SASV_DEMO=0 streamlit run app.py`")


# =============================================================================== filtres

PRESETS = ["30 derniers jours", "7 derniers jours", "90 derniers jours", "Mois en cours",
           "Année en cours", "12 derniers mois", "Tout l'historique", "Période personnalisée"]


def _persist(name, default):
    k = f"_w_{name}"
    if k not in S:
        S[k] = S.flt.get(name, default)
    return k


def filter_bar(df: pd.DataFrame, page: str):
    """US-302 — filtres multidimensionnels (période, région, produit, canal)."""
    ref = df["jour"].max()
    lo = df["jour"].min()
    with st.container(border=True):
        c = st.columns([1.35, 1, 1, 1, 1.2])
        preset = c[0].selectbox("Période", PRESETS, key=_persist("preset", PRESETS[0]),
                                help="Les variations sont calculées par rapport à la période précédente de même durée.")
        canal = c[1].multiselect("Canal", data.CANAUX, key=_persist("canal", []), placeholder="Tous")
        regions = sorted(df["region"].dropna().unique().tolist())
        region = c[2].multiselect("Région", regions, key=_persist("region", []), placeholder="Toutes")
        familles = sorted(df["famille"].dropna().unique().tolist())
        famille = c[3].multiselect("Famille", familles, key=_persist("famille", []), placeholder="Toutes")
        prods = sorted(df[df["famille"].isin(famille)]["produit"].unique().tolist() if famille
                       else df["produit"].unique().tolist())
        kp = _persist("produit", [])
        S[kp] = [p for p in S[kp] if p in prods]
        produit = c[4].multiselect("Produit", prods, key="_w_produit", placeholder="Tous")

        if preset == "7 derniers jours":
            start, end = ref - pd.Timedelta(days=6), ref
        elif preset == "30 derniers jours":
            start, end = ref - pd.Timedelta(days=29), ref
        elif preset == "90 derniers jours":
            start, end = ref - pd.Timedelta(days=89), ref
        elif preset == "Mois en cours":
            start, end = ref.to_period("M").to_timestamp(), ref
        elif preset == "Année en cours":
            start, end = pd.Timestamp(ref.year, 1, 1), ref
        elif preset == "12 derniers mois":
            start, end = ref - pd.DateOffset(months=12) + pd.Timedelta(days=1), ref
        elif preset == "Tout l'historique":
            start, end = lo, ref
        else:
            k = _persist("dates", (ref.date() - timedelta(days=29), ref.date()))
            rng = st.date_input("Dates", key=k, min_value=lo.date(), max_value=ref.date(), format="DD/MM/YYYY")
            if isinstance(rng, (list, tuple)) and len(rng) == 2:
                start, end = pd.Timestamp(rng[0]), pd.Timestamp(rng[1])
            else:
                start, end = pd.Timestamp(rng[0] if isinstance(rng, (list, tuple)) else rng), ref
            S.flt["dates"] = S[k]
    for n, v in (("preset", preset), ("canal", canal), ("region", region), ("famille", famille), ("produit", produit)):
        S.flt[n] = v

    mask = pd.Series(True, index=df.index)
    if canal:
        mask &= df["canal"].isin(canal)
    if region:
        mask &= df["region"].isin(region)
    if famille:
        mask &= df["famille"].isin(famille)
    if produit:
        mask &= df["produit"].isin(produit)
    base = df[mask]
    length = (end - start).days + 1
    cur = base[(base["jour"] >= start) & (base["jour"] <= end)]
    prev = base[(base["jour"] >= start - pd.Timedelta(days=length)) & (base["jour"] < start)]

    sig = (page, preset, tuple(canal), tuple(region), tuple(famille), tuple(produit), str(start.date()), str(end.date()))
    if S.get("_last_filter") != sig:
        if S.get("_last_filter") is not None:
            log("CONSULTATION", f"{page} — filtres : {preset}, canal={canal or 'tous'}, région={region or 'toutes'}, "
                                f"famille={famille or 'toutes'}, produits={len(produit) or 'tous'}")
        S["_last_filter"] = sig
    return cur, prev, start, end


def pct(a, b):
    return None if not b else (a / b - 1) * 100


def no_sales(df: pd.DataFrame) -> bool:
    if df.empty:
        st.info("Aucune vente disponible sur votre périmètre. Contactez la Direction pour vérifier vos habilitations.")
        return True
    return False


# =============================================================================== pages

def page_accueil():
    u = user()
    meta = f"Connecté : {S.login} · {ROLES[S.role]['label']} · {perimeter_label(u)}"
    main = next(((p, lab) for p, lab in (("dashboard", "Accéder au tableau de bord"), ("import", "Déposer les ventes"),
                                         ("admin", "Gérer les accès"), ("audit", "Ouvrir le journal d'audit"))
                 if can(p)), ("aide", "Consulter l'aide"))
    if ui.hero("Suivi automatisé et sécurisé des ventes",
               "Choisissez l'indicateur que vous souhaitez analyser.", meta=meta, button=main[1]):
        st.switch_page(PAGES[main[0]])

    has_sales = can("dashboard") and not sales().empty
    cards = []
    if has_sales:
        df = sales()
        ref = df["jour"].max()
        cur = df[df["jour"] > ref - pd.Timedelta(days=30)]
        prev = df[(df["jour"] <= ref - pd.Timedelta(days=30)) & (df["jour"] > ref - pd.Timedelta(days=60))]
        d = pct(cur["montant"].sum(), prev["montant"].sum())
        cards.append(dict(key="ca", word1="Chiffre", word2="d'Affaires", title="Suivre le chiffre d'affaires",
                          desc="CA consolidé des 30 derniers jours, tous canaux confondus.",
                          value=data.fmt_fcfa(cur["montant"].sum()),
                          delta=(f"{'▲' if d >= 0 else '▼'} {d:+.1f} %" if d is not None else ""),
                          delta_cls="up" if (d or 0) >= 0 else "down", target="dashboard", variant="a",
                          accent_second=False))
        ag = cur[cur["canal"] == "Agence"]
        cards.append(dict(key="agences", word1="Ventes", word2="Agences", title="Collecte des agences",
                          desc="Dépôt sécurisé des fichiers CSV et contrôle d'intégrité.",
                          value=f"{data.fmt_int(len(ag))} ventes / 30 j",
                          target="import" if can("import") else "dashboard", variant="b"))
    if can("alertes"):
        a = current_alerts()
        n = len(a)
        crit = int((a["severite"] == "critique").sum()) if n else 0
        cards.append(dict(key="alertes", word1="Alertes", word2="Actives", title="Signaux faibles",
                          desc="Baisses de CA, retards sur objectif, collectes interrompues.",
                          value=f"{n} alerte{'s' if n > 1 else ''}", delta=f"dont {crit} critique(s)" if n else "",
                          delta_cls="down" if crit else "", target="alertes", variant="a"))
    if can("import") and not has_sales:
        mine = data.ingest_history()
        mine = mine[mine["user"] == S.login]
        cards.append(dict(key="import", word1="Dépôt", word2="des Ventes", title="Transmettre les ventes de l'agence",
                          desc="Dépôt sécurisé du fichier CSV et contrôle automatique.",
                          value=f"{len(mine)} dépôt{'s' if len(mine) > 1 else ''} effectué{'s' if len(mine) > 1 else ''}",
                          target="import", variant="a"))
    if can("audit"):
        ok, nb, _, _ = audit.verify_chain()
        pend = len(security.pending_audit_requests()) if S.role == "auditeur" else 0
        cards.append(dict(key="audit", word1="Journal", word2="d'Audit", title="Tracer chaque action",
                          desc="Journal chaîné HMAC-SHA256, conservé 5 ans.",
                          value="Chaîne intègre" if ok else "Altération détectée",
                          delta=(f"· {pend} demande(s) d'accès" if pend else f"· {data.fmt_int(nb)} entrées"),
                          delta_cls="down" if pend else "", target="audit", variant="b"))
    if can("admin"):
        us = security.list_users()
        locked = sum(security.is_locked(x) for x in us.values())
        cards.append(dict(key="admin", word1="Gestion", word2="des Accès", title="Administrer les comptes",
                          desc="Comptes, rôles, périmètres, déverrouillages et MFA.",
                          value=f"{len(us)} comptes", delta=f"· {locked} verrouillé(s)" if locked else "",
                          delta_cls="down" if locked else "", target="admin", variant="a"))
    if can("rapports") and len(cards) < 4:
        cards.append(dict(key="rapports", word1="Rapports", word2="& Exports", title="Exporter le reporting",
                          desc="Rapport PDF périodique, export CSV et journal ERP.", target="rapports", variant="a"))
    if len(cards) < 4:
        cards.append(dict(key="compte", word1="Mon", word2="Compte", title="Sécuriser mon accès",
                          desc="Mot de passe, double authentification et périmètre.", target="compte", variant="b"))

    cols = st.columns(4, gap="medium")
    for col, c in zip(cols, cards[:4]):
        with col:
            target = c.pop("target")
            if ui.card(**c):
                st.switch_page(PAGES[target])

    ui.section("Notre actualité")
    n1, n2, n3 = st.columns(3, gap="medium")
    if has_sales:
        df = sales()
        ref = df["jour"].max()
        cur = df[df["jour"] > ref - pd.Timedelta(days=30)]
        top = cur.groupby("produit", observed=True)["montant"].sum().sort_values(ascending=False)
        best_pv = cur.groupby("point_vente", observed=True)["montant"].sum().sort_values(ascending=False)
        with n1:
            ui.news("g", "TOP PRODUIT", data.fmt_date(ref), f"{top.index[0]} en tête des ventes",
                    f"{data.fmt_fcfa(top.iloc[0])} sur 30 jours, soit {top.iloc[0] / top.sum() * 100:.1f} % du CA du périmètre.")
        with n2:
            last_day = df[df["jour"] == ref]
            ui.news("p", "COLLECTE", data.fmt_date(ref), f"{data.fmt_int(len(last_day))} ventes remontées hier",
                    f"Flux POS, e-commerce et agences consolidés automatiquement. "
                    f"Meilleur point de vente du mois : {best_pv.index[0]}.")
    elif can("audit"):
        with n1:
            log_df = audit.read_all()
            ui.news("g", "ACTIVITÉ", data.fmt_date(datetime.now()), f"{len(log_df)} événements journalisés",
                    "Connexions, consultations, exports et modifications tracés en continu.")
        with n2:
            sus = audit.suspicious_activity(audit.read_all())
            ui.news("p", "SURVEILLANCE", data.fmt_date(datetime.now()), f"{len(sus)} comportement(s) suspect(s)",
                    "Échecs d'authentification répétés et exports massifs sur 24 h.")
    elif can("import"):
        mine = data.ingest_history()
        mine = mine[mine["user"] == S.login]
        with n1:
            last = (f"Dernier dépôt le {data.fmt_date(mine['ts'].iloc[0])} : {mine['rows'].iloc[0]} vente(s) intégrée(s)."
                    if len(mine) else "Aucun dépôt pour l'instant.")
            ui.news("g", "MES DÉPÔTS", data.fmt_date(datetime.now()), f"{len(mine)} fichier(s) transmis", last)
        with n2:
            ui.news("p", "CONTRÔLES", data.fmt_date(datetime.now()), "Chaque ligne est vérifiée avant intégration",
                    "Format, dates, montants, référentiels, doublons et périmètre de l'agence.")
    elif can("admin"):
        us = security.list_users()
        with n1:
            ui.news("g", "COMPTES", data.fmt_date(datetime.now()), f"{len(us)} comptes enregistrés",
                    f"{sum(not x['active'] for x in us.values())} désactivé(s), "
                    f"{sum(security.is_locked(x) for x in us.values())} verrouillé(s).")
        with n2:
            ui.news("p", "HABILITATIONS", data.fmt_date(datetime.now()), "Moindre privilège",
                    "Chaque compte n'accède qu'aux pages de son rôle et à son périmètre régions / familles.")
    with n3:
        ok, nb, _, msg = audit.verify_chain()
        ui.news("d", "SÉCURITÉ", data.fmt_date(datetime.now()),
                "Journal d'audit intègre" if ok else "Alerte d'intégrité du journal",
                f"{msg} Double authentification active pour tous les comptes.")


def page_dashboard():
    df = sales()
    ui.hero("Tableau de bord des ventes", "Vision consolidée, filtrable et rafraîchie en continu.",
            meta=perimeter_label(user()))
    if no_sales(df):
        return
    cur, prev, start, end = filter_bar(df, "Tableau de bord")

    @st.fragment(run_every="60s")
    def live():
        if session_expired():  # le rafraîchissement automatique ne doit pas maintenir l'affichage d'une session expirée
            st.rerun()
        upd = data.last_update()
        if S.get("_seen_update") and upd > S["_seen_update"]:
            S["_seen_update"] = upd
            st.toast("Nouvelles ventes collectées — mise à jour du tableau de bord.", icon="🔄")
            st.rerun()
        S["_seen_update"] = upd
        st.caption(f"🟢 Données à jour au {data.fmt_date(df['jour'].max())} · dernière collecte {upd:%d/%m/%Y %H:%M} · "
                   f"vérification automatique chaque minute · période {data.fmt_date(start)} → {data.fmt_date(end)}")
    live()

    if cur.empty:
        st.info("Aucune vente pour cette sélection.")
        return

    ca, ca_p = cur["montant"].sum(), prev["montant"].sum()
    n, n_p = len(cur), len(prev)
    brut, brut_p = (cur["qte"] * cur["prix_unit"]).sum(), (prev["qte"] * prev["prix_unit"]).sum()
    rem = cur["remise_fcfa"].sum() / brut * 100 if brut else 0
    rem_p = prev["remise_fcfa"].sum() / brut_p * 100 if brut_p else 0
    k = st.columns(5, gap="small")
    with k[0]:
        ui.kpi("Chiffre d'affaires", data.fmt_fcfa(ca), pct(ca, ca_p))
    with k[1]:
        ui.kpi("Transactions", data.fmt_int(n), pct(n, n_p))
    with k[2]:
        ui.kpi("Panier moyen", data.fmt_fcfa(ca / n, short=False), pct(ca / n, ca_p / n_p if n_p else 0))
    with k[3]:
        ui.kpi("Articles vendus", data.fmt_int(cur["qte"].sum()), pct(cur["qte"].sum(), prev["qte"].sum()))
    with k[4]:
        ui.kpi("Taux de remise", f"{rem:.2f} %".replace(".", ","), None,
               sub=f"{rem - rem_p:+.2f} pt vs période précédente" if brut_p else "")

    st.write("")
    t1, t2, t3, t4, t5 = st.tabs(["Évolution", "Géographie", "Produits", "Points de vente & vendeurs", "Données détaillées"])

    days = (end - start).days + 1
    gran, label = ("jour", "jour") if days <= 45 else (("semaine", "semaine") if days <= 200 else ("mois", "mois"))

    with t1:
        ts = cur.groupby([gran, "canal"], observed=True)["montant"].sum().reset_index()
        fig = go.Figure()
        for c in data.CANAUX:
            s = ts[ts["canal"] == c]
            if s.empty:
                continue
            fig.add_trace(go.Scatter(x=s[gran], y=s["montant"], name=c, mode="lines",
                                     line=dict(color=CANAL_COLORS[c], width=2),
                                     hovertemplate=f"<b>{c}</b><br>%{{x|%d/%m/%Y}}<br>%{{y:,.0f}} FCFA<extra></extra>"))
            fig.add_annotation(x=s[gran].iloc[-1], y=s["montant"].iloc[-1], text=c, showarrow=False,
                               xanchor="left", xshift=6, font=dict(size=11, color="#3A3A3A"))
        fig.update_layout(title=f"CA par canal et par {label}", hovermode="x unified")
        ui.style_fig(fig, 360)
        fig.update_layout(margin=dict(r=80))
        fig.update_yaxes(tickformat="~s", ticksuffix=" ")
        st.plotly_chart(fig, width="stretch")

        a, b = st.columns(2, gap="large")
        with a:
            share = cur.groupby("canal", observed=True)["montant"].sum().reindex(data.CANAUX).dropna()
            sp = prev.groupby("canal", observed=True)["montant"].sum()
            f2 = go.Figure(go.Bar(
                y=share.index, x=share.values, orientation="h",
                marker=dict(color=[CANAL_COLORS[c] for c in share.index], cornerradius=4),
                text=[f"{v / ca * 100:.1f} %  ·  {data.fmt_fcfa(v)}" for v in share.values], textposition="outside",
                customdata=[pct(share[c], sp.get(c, 0)) or 0 for c in share.index],
                hovertemplate="<b>%{y}</b><br>%{x:,.0f} FCFA<br>%{customdata:+.1f} % vs période préc.<extra></extra>"))
            f2.update_layout(title="Répartition du CA par canal")
            ui.style_fig(f2, 260, legend=False)
            f2.update_xaxes(visible=False, range=[0, share.max() * 1.45])
            st.plotly_chart(f2, width="stretch")
        with b:
            wd = cur.groupby("jour_sem")["montant"].sum() / cur.groupby("jour_sem")["jour"].nunique()
            f3 = go.Figure(go.Bar(x=[data.JOURS_FR[i] for i in wd.index], y=wd.values,
                                  marker=dict(color=PURPLE, cornerradius=4),
                                  hovertemplate="<b>%{x}</b><br>%{y:,.0f} FCFA / jour<extra></extra>"))
            f3.update_layout(title="CA moyen selon le jour de la semaine")
            ui.style_fig(f3, 260, legend=False)
            f3.update_yaxes(tickformat="~s")
            st.plotly_chart(f3, width="stretch")

    with t2:
        g = cur.groupby("region", observed=True).agg(ca=("montant", "sum"), tx=("ref", "count")).sort_values("ca")
        gp = prev.groupby("region", observed=True)["montant"].sum()
        g["var"] = [pct(g.loc[r, "ca"], gp.get(r, 0)) for r in g.index]
        a, b = st.columns([1.35, 1], gap="large")
        with a:
            f = go.Figure(go.Bar(y=g.index.astype(str), x=g["ca"], orientation="h",
                                 marker=dict(color=PURPLE, cornerradius=4),
                                 text=[data.fmt_fcfa(v) for v in g["ca"]], textposition="outside",
                                 customdata=g[["tx", "var"]].fillna(0).values,
                                 hovertemplate="<b>%{y}</b><br>%{x:,.0f} FCFA<br>%{customdata[0]:,} transactions"
                                               "<br>%{customdata[1]:+.1f} % vs période préc.<extra></extra>"))
            f.update_layout(title="CA par région")
            ui.style_fig(f, 90 + 36 * len(g), legend=False)
            f.update_xaxes(visible=False, range=[0, g["ca"].max() * 1.3])
            st.plotly_chart(f, width="stretch")
        with b:
            st.markdown("**Évolution par région**")
            tab = g.sort_values("ca", ascending=False).reset_index()
            tab["part"] = tab["ca"] / ca * 100
            st.dataframe(tab[["region", "ca", "part", "var"]], hide_index=True, width="stretch",
                         height=38 + 35 * len(tab),
                         column_config={
                             "region": "Région",
                             "ca": st.column_config.NumberColumn("CA (FCFA)", format="localized"),
                             "part": st.column_config.ProgressColumn("Part du CA", format="%.1f %%", min_value=0,
                                                                     max_value=float(tab["part"].max())),
                             "var": st.column_config.NumberColumn("Var. %", format="%+.1f %%")})

    with t3:
        a, b = st.columns(2, gap="large")
        with a:
            fm = cur.groupby("famille", observed=True)["montant"].sum().sort_values()
            f = go.Figure(go.Bar(y=fm.index.astype(str), x=fm.values, orientation="h",
                                 marker=dict(color=RED, cornerradius=4),
                                 text=[f"{v / ca * 100:.1f} %" for v in fm.values], textposition="outside",
                                 hovertemplate="<b>%{y}</b><br>%{x:,.0f} FCFA<extra></extra>"))
            f.update_layout(title="CA par famille de produits")
            ui.style_fig(f, max(220, 90 + 36 * len(fm)), legend=False)
            f.update_xaxes(visible=False, range=[0, fm.max() * 1.2])
            st.plotly_chart(f, width="stretch")
        with b:
            tp = cur.groupby("produit", observed=True).agg(ca=("montant", "sum"), q=("qte", "sum")).nlargest(10, "ca").sort_values("ca")
            f = go.Figure(go.Bar(y=tp.index.astype(str), x=tp["ca"], orientation="h",
                                 marker=dict(color=ORANGE, cornerradius=4),
                                 text=[data.fmt_fcfa(v) for v in tp["ca"]], textposition="outside",
                                 customdata=tp["q"], hovertemplate="<b>%{y}</b><br>%{x:,.0f} FCFA<br>%{customdata:,} unités<extra></extra>"))
            f.update_layout(title="Top 10 produits")
            ui.style_fig(f, max(220, 90 + 32 * len(tp)), legend=False)
            f.update_xaxes(visible=False, range=[0, tp["ca"].max() * 1.35])
            st.plotly_chart(f, width="stretch")
        hm = cur.pivot_table(index="famille", columns="canal", values="montant", aggfunc="sum", observed=True).fillna(0)
        hm = hm[[c for c in data.CANAUX if c in hm.columns]]
        f = go.Figure(go.Heatmap(z=hm.values, x=hm.columns, y=hm.index.astype(str), colorscale=ui.SEQ,
                                 xgap=2, ygap=2, text=[[data.fmt_fcfa(v) for v in r] for r in hm.values],
                                 texttemplate="%{text}", hovertemplate="%{y} · %{x}<br>%{z:,.0f} FCFA<extra></extra>",
                                 colorbar=dict(title="FCFA", tickformat="~s", thickness=10)))
        f.update_layout(title="Croisement famille × canal")
        ui.style_fig(f, 320, legend=False)
        st.plotly_chart(f, width="stretch")

    with t4:
        pv = cur.groupby(["point_vente"], observed=True).agg(
            canal=("canal", lambda s: s.mode().iat[0]),
            ca=("montant", "sum"), tx=("ref", "count"), panier=("montant", "mean"),
            derniere=("jour", "max")).reset_index().sort_values("ca", ascending=False)
        pvp = prev.groupby("point_vente", observed=True)["montant"].sum()
        pv["var"] = [pct(r.ca, pvp.get(r.point_vente, 0)) for r in pv.itertuples()]
        pv["tend"] = [cur[cur["point_vente"] == p].groupby("semaine")["montant"].sum().tolist() for p in pv["point_vente"]]
        st.markdown("**Performance des points de vente**")
        st.dataframe(pv[["point_vente", "canal", "ca", "var", "tx", "panier", "tend", "derniere"]],
                     hide_index=True, width="stretch",
                     column_config={
                         "point_vente": "Point de vente", "canal": "Canal",
                         "ca": st.column_config.ProgressColumn("CA (FCFA)", format="compact", min_value=0, max_value=float(pv["ca"].max())),
                         "var": st.column_config.NumberColumn("Var. %", format="%+.1f %%"),
                         "tx": st.column_config.NumberColumn("Transactions", format="localized"),
                         "panier": st.column_config.NumberColumn("Panier moyen", format="%.0f"),
                         "tend": st.column_config.LineChartColumn("Tendance hebdo"),
                         "derniere": st.column_config.DateColumn("Dernière vente", format="DD/MM/YYYY")})
        st.markdown("**Classement des vendeurs**")
        vd = cur.groupby("vendeur", observed=True).agg(ca=("montant", "sum"), tx=("ref", "count"),
                                                        remise=("remise_pct", "mean")).reset_index().sort_values("ca", ascending=False)
        vdp = prev.groupby("vendeur", observed=True)["montant"].sum()
        vd["var"] = [pct(r.ca, vdp.get(r.vendeur, 0)) for r in vd.itertuples()]
        vd.insert(0, "rang", range(1, len(vd) + 1))
        st.dataframe(vd, hide_index=True, width="stretch",
                     column_config={"rang": "#", "vendeur": "Vendeur",
                                    "ca": st.column_config.ProgressColumn("CA (FCFA)", format="compact", min_value=0, max_value=float(vd["ca"].max())),
                                    "tx": st.column_config.NumberColumn("Transactions", format="localized"),
                                    "remise": st.column_config.NumberColumn("Remise moy.", format="%.2f %%"),
                                    "var": st.column_config.NumberColumn("Var. %", format="%+.1f %%")})

    with t5:
        st.caption(f"{data.fmt_int(len(cur))} transactions sur la période (5 000 plus récentes affichées).")
        show = cur.sort_values("jour", ascending=False).head(5000)
        st.dataframe(show[data.COLUMNS], hide_index=True, width="stretch", height=420,
                     column_config={"jour": st.column_config.DateColumn("Date", format="DD/MM/YYYY"),
                                    "montant": st.column_config.NumberColumn("Montant", format="localized")})


def page_alertes():
    ui.hero("Alertes et notifications", "Détection automatique des décrochages commerciaux.",
            meta=perimeter_label(user()))
    c1, c2 = st.columns([1, 3])
    days = c1.selectbox("Fenêtre d'analyse", [7, 30, 90], index=1, format_func=lambda d: f"{d} derniers jours",
                        help="Chaque règle compare la fenêtre choisie à la fenêtre précédente de même durée.")
    a = current_alerts(days)
    with c2:
        if a.empty:
            st.success("Aucune alerte active sur votre périmètre.", icon="✅")
        else:
            counts = a["severite"].value_counts()
            st.markdown(" ".join(
                f"<span class='pill' style='background:{al.SEVERITY[s]['color']}1A;color:{al.SEVERITY[s]['color']}'>"
                f"{al.SEVERITY[s]['icon']} {counts.get(s, 0)} {s}</span>" for s in al.SEVERITY), unsafe_allow_html=True)

    for r in a.itertuples():
        sv = al.SEVERITY[r.severite]
        st.markdown(f"<div class='alert-row' style='border-color:{sv['color']}'>"
                    f"<div class='sev' style='color:{sv['color']}'>{sv['icon']} {r.severite}</div>"
                    f"<div><div class='c'>{html.escape(r.cible)} <span style='font-weight:400;color:#6B6B6B'>· "
                    f"{html.escape(r.libelle_regle)}</span></div>"
                    f"<div class='m'>{html.escape(r.message)}</div></div></div>", unsafe_allow_html=True)

    if not a.empty:
        ui.section("Notifier par e-mail")
        with st.form("mail", border=True):
            m1, m2 = st.columns([2, 1])
            to = m1.text_input("Destinataire(s)", value="direction.commerciale@entreprise.cm")
            sev = m2.multiselect("Criticité", list(al.SEVERITY), default=list(al.SEVERITY))
            if st.form_submit_button("Envoyer la notification"):
                sel = a[a["severite"].isin(sev)]
                dest = [m.strip() for m in re.split(r"[;,]", to or "") if m.strip()]
                if not dest or not all(EMAIL_RX.fullmatch(m) for m in dest):
                    st.error("Adresse(s) e-mail invalide(s). Séparez plusieurs destinataires par « ; ».")
                elif sel.empty:
                    st.warning("Aucune alerte pour la criticité sélectionnée.")
                else:
                    to = "; ".join(dest)
                    al.queue_email(to, sel, S.login)
                    log("NOTIFICATION_EMAIL", f"{len(sel)} alerte(s) → {to}")
                    st.success(f"{len(sel)} alerte(s) envoyée(s) à {to}.")

    if S.role in ("direction", "manager"):
        ui.section("Règles d'alerte")
        rules = al.load_rules()
        rdf = pd.DataFrame([{"id": k, "Règle": v["label"], "Seuil": v["seuil"], "Unité": v["unite"], "Active": v["actif"]}
                            for k, v in rules.items()])
        ed = st.data_editor(rdf, hide_index=True, width="stretch", disabled=["id", "Règle", "Unité"],
                            column_config={"id": None, "Seuil": st.column_config.NumberColumn(min_value=0.0, max_value=100.0, step=0.5)},
                            key="rules_editor")
        with st.container(key="black-rules"):
            if st.button("Enregistrer les règles"):
                changes = []
                for row in ed.itertuples():
                    old = rules[row.id]
                    seuil = old["seuil"] if pd.isna(row.Seuil) else float(row.Seuil)
                    actif = bool(row.Active)
                    if old["seuil"] != seuil or old["actif"] != actif:
                        changes.append(f"{row.id}: seuil {old['seuil']}→{seuil}, actif {old['actif']}→{actif}")
                    rules[row.id].update(seuil=seuil, actif=actif)
                al.save_rules(rules)
                log("MODIF_REGLE_ALERTE", "; ".join(changes) or "aucun changement")
                st.success("Règles enregistrées.")
                st.rerun()

    ob = al.outbox()
    if not ob.empty:
        with st.expander(f"Historique des notifications envoyées ({len(ob)})"):
            st.dataframe(ob.sort_values("ts", ascending=False)[["ts", "to", "by", "subject"]], hide_index=True,
                         width="stretch")


def page_import():
    u = user()
    ui.hero("Dépôt sécurisé des ventes d'agence", "Import CSV contrôlé, horodaté et tracé.",
            meta=perimeter_label(u))
    a, b = st.columns([1.4, 1], gap="large")
    with b:
        st.markdown("**Format attendu**")
        st.caption("Séparateur `;` ou `,`, encodage UTF-8, une ligne par vente.")
        st.code(";".join(data.COLUMNS), language=None)
        tmpl = pd.DataFrame([{"ref": "TX-20261013-900001", "jour": "2026-10-13", "canal": "Agence", "region": "Nord",
                              "ville": "Garoua", "point_vente": "AGENCE-Nord", "vendeur": "ABBA M.",
                              "produit": "Riz parfume 25kg", "famille": "Alimentaire", "qte": 2, "prix_unit": 18500,
                              "remise_pct": 0, "montant": 37000, "devise": "FCFA"}])
        st.download_button("Télécharger le modèle CSV", tmpl.to_csv(sep=";", index=False).encode("utf-8"),
                           "modele_depot_agence.csv", "text/csv", width="stretch")
        st.markdown("**Contrôles appliqués**")
        st.markdown("- Empreinte SHA-256 : refus d'un fichier déjà déposé\n- Schéma, types et dates\n"
                    "- Cohérence `qte × prix × (1 − remise) = montant`\n- Référentiels canal / région / famille\n"
                    "- Doublons de références\n- Respect de votre périmètre géographique")
    with a:
        if S.get("_import_done"):
            st.success(S.pop("_import_done"))
            st.balloons()
        up = st.file_uploader("Fichier des ventes (CSV)", type=["csv"], help="Taille maximale : 20 Mo.",
                              key=f"upload_{S.get('_upload_n', 0)}")
        if up is not None:
            raw = up.getvalue()
            if len(raw) > 20 * 1024 * 1024:
                st.error("Fichier trop volumineux (20 Mo max).")
                return
            existing = set(data.load_sales()["ref"])
            valid, rejected, rep = data.validate_upload(raw, existing)
            if rep["errors"]:
                for e in rep["errors"]:
                    st.error(e)
                log("IMPORT_CSV", f"{up.name} refusé : {'; '.join(rep['errors'])}", "ECHEC")
                return
            for col, motif in (("regions", "Hors de votre périmètre géographique"),
                               ("familles", "Famille hors de votre périmètre")):
                if u.get(col):
                    out = ~valid["region" if col == "regions" else "famille"].isin(u[col])
                    if out.any():
                        rejected = pd.concat([rejected, valid[out].assign(motif=motif)])
                        valid = valid[~out]
            rep["valid"], rep["rejected"] = len(valid), len(rejected)
            m = st.columns(3)
            m[0].metric("Lignes lues", data.fmt_int(rep["total"]))
            m[1].metric("Lignes valides", data.fmt_int(rep["valid"]))
            m[2].metric("Lignes rejetées", data.fmt_int(rep["rejected"]))
            st.caption(f"Empreinte SHA-256 : `{rep['sha256']}`")
            if len(rejected):
                with st.expander(f"Détail des {len(rejected)} rejets", expanded=True):
                    st.dataframe(rejected[["ref", "jour", "point_vente", "montant", "motif"]], hide_index=True,
                                 width="stretch")
            if len(valid):
                st.dataframe(valid.head(50), hide_index=True, width="stretch", height=220)
                with st.container(key="black-import"):
                    if st.button(f"Valider l'intégration de {len(valid)} vente(s)", width="stretch"):
                        name = data.commit_upload(valid, rep, S.login, up.name)
                        log("IMPORT_CSV", f"{up.name} → {name} : {rep['valid']} lignes intégrées, {rep['rejected']} rejetées, "
                                          f"sha256={rep['sha256'][:16]}")
                        # Nouveau sélecteur vide : sinon le même fichier serait revalidé et refusé comme doublon.
                        S["_upload_n"] = S.get("_upload_n", 0) + 1
                        S["_import_done"] = (f"{rep['valid']} vente(s) intégrée(s) depuis « {up.name} ». "
                                             "Le tableau de bord est mis à jour.")
                        st.rerun()
    ui.section("Historique des dépôts")
    h = data.ingest_history()
    if S.role == "agence":
        h = h[h["user"] == S.login]
    if h.empty:
        st.caption("Aucun dépôt pour l'instant.")
    else:
        st.dataframe(h[["ts", "user", "file", "rows", "sha256"]], hide_index=True, width="stretch",
                     column_config={"ts": "Date", "user": "Déposant", "file": "Fichier", "rows": "Lignes", "sha256": "Empreinte"})


def page_rapports():
    df = sales()
    ui.hero("Rapports et exports", "Rapport périodique PDF, données filtrées et journal ERP.",
            meta=perimeter_label(user()))
    if no_sales(df):
        return
    cur, prev, start, end = filter_bar(df, "Rapports")
    st.caption(f"Sélection : {data.fmt_int(len(cur))} transactions · {data.fmt_fcfa(cur['montant'].sum(), short=False)} · "
               f"du {data.fmt_date(start)} au {data.fmt_date(end)}")
    if cur.empty:
        st.info("Aucune vente pour cette sélection : rien à exporter.")
        return
    c1, c2, c3 = st.columns(3, gap="medium")
    with c1:
        sig = S.get("_last_filter")
        if ui.card("pdf", "Rapport", "PDF", "Rapport de ventes périodique",
                   "KPIs, évolution par canal, régions, familles, top produits.", button="Générer le rapport"):
            with st.spinner("Génération du PDF…"):
                S["_pdf"] = (sig, report.build_pdf(cur, prev, start, end, S.login, perimeter_label(user())))
        if S.get("_pdf") and S["_pdf"][0] != sig:
            S.pop("_pdf")  # filtres modifiés depuis la génération : le PDF ne correspond plus à la sélection
            st.caption("Les filtres ont changé : générez à nouveau le rapport.")
        if S.get("_pdf"):
            st.download_button("Télécharger le PDF", S["_pdf"][1], f"SASV_rapport_{start:%Y%m%d}_{end:%Y%m%d}.pdf",
                               "application/pdf", width="stretch",
                               on_click=lambda: log("EXPORT_PDF", f"{start:%d/%m/%Y}-{end:%d/%m/%Y}, {len(cur)} ventes"))
    with c2:
        if ui.card("csv", "Données", "CSV", "Export des ventes filtrées",
                   "Transactions détaillées au format CSV (séparateur ;).", button="Préparer l'export"):
            S["_csv_ready"] = True
        if S.get("_csv_ready"):
            st.download_button("Télécharger le CSV", cur[data.COLUMNS].to_csv(sep=";", index=False).encode("utf-8-sig"),
                               f"SASV_ventes_{start:%Y%m%d}_{end:%Y%m%d}.csv", "text/csv", width="stretch",
                               on_click=lambda: log("EXPORT_CSV", f"{len(cur)} lignes"))
    with c3:
        if ui.card("erp", "Journal", "ERP", "Passerelle comptable",
                   "Écritures agrégées jour × point de vente × famille.", button="Préparer le journal"):
            S["_erp_ready"] = True
        if S.get("_erp_ready"):
            csv, ctl = report.erp_journal(cur)
            st.download_button("Télécharger le journal", csv, f"SASV_journal_ERP_{end:%Y%m%d}.csv", "text/csv",
                               width="stretch",
                               on_click=lambda: log("EXPORT_ERP", f"{ctl['lignes']} écritures, total {ctl['total_ttc']}"))
            ok = ctl["total_ttc"] == int(cur["montant"].sum())
            st.caption(f"Contrôle de réconciliation : {data.fmt_int(ctl['lignes'])} écritures · total "
                       f"{data.fmt_fcfa(ctl['total_ttc'], short=False)} {'✅ conforme' if ok else '❌ écart'}")


def audit_access_admin():
    """Le Responsable sécurité instruit les demandes d'accès temporaire au journal (ex. Direction Générale)."""
    users = security.list_users()
    pend = security.pending_audit_requests()
    grants = security.active_audit_grants()
    if not pend and not grants:
        return
    ui.section("Demandes d'accès au journal")
    for login, req in pend.items():
        with st.container(border=True):
            st.markdown(f"**{html.escape(users[login]['name'])}** ({login}) — demande du "
                        f"{datetime.fromisoformat(req['ts']):%d/%m/%Y à %H:%M}  \n*Motif :* {html.escape(req['motif'])}")
            c = st.columns([1.2, 1, 1])
            hours = c[0].selectbox("Durée", AUDIT_GRANT_HOURS, format_func=lambda h: f"{h} heure{'s' if h > 1 else ''}",
                                   key=f"grant_h_{login}", label_visibility="collapsed")
            with c[1], st.container(key=f"black-grant-{login}"):
                if st.button("Accorder", key=f"grant_{login}", width="stretch"):
                    until = security.grant_audit_access(login, hours, S.login)
                    log("AUDIT_ACCES_ACCORDE", f"{login} jusqu'au {datetime.fromisoformat(until):%d/%m/%Y %H:%M} — motif : {req['motif']}")
                    st.rerun()
            with c[2]:
                if st.button("Refuser", key=f"deny_{login}", width="stretch"):
                    security.deny_audit_access(login)
                    log("AUDIT_ACCES_REFUSE", f"{login} — motif : {req['motif']}")
                    st.rerun()
    for login, until in grants.items():
        c = st.columns([3, 1])
        c[0].markdown(f"🔓 **{html.escape(users[login]['name'])}** ({login}) : accès accordé jusqu'au "
                      f"{datetime.fromisoformat(until):%d/%m/%Y à %H:%M}")
        if c[1].button("Révoquer", key=f"revoke_{login}", width="stretch"):
            security.revoke_audit_access(login)
            log("AUDIT_ACCES_REVOQUE", login)
            st.rerun()


def page_audit():
    ui.hero("Journal d'audit", "Piste d'audit infalsifiable : connexions, consultations, modifications, exports.",
            meta=f"Conservation {AUDIT_RETENTION_YEARS} ans · chaînage HMAC-SHA256")
    if S.role == "auditeur":
        audit_access_admin()
    elif security.has_audit_grant(user()):
        st.info(f"Accès temporaire en lecture accordé jusqu'au "
                f"{datetime.fromisoformat(user()['audit_access_until']):%d/%m/%Y à %H:%M}. Vos consultations sont journalisées.",
                icon="🔓")
    ok, nb, _, msg = audit.verify_chain()
    df = audit.read_all()
    k = st.columns(4)
    with k[0]:
        ui.kpi("Intégrité", "Intègre ✅" if ok else "Altérée ⛔", None, sub=f"{data.fmt_int(nb)} entrées vérifiées")
    day = df[df["ts"] >= datetime.now() - timedelta(hours=24)] if not df.empty else df
    with k[1]:
        ui.kpi("Connexions 24 h", data.fmt_int(int(((day["action"] == "MFA") & (day["status"] == "OK")).sum()) if not day.empty else 0), None, sub="sessions ouvertes")
    with k[2]:
        ui.kpi("Échecs d'authentification", data.fmt_int(int((day["action"].isin(["LOGIN", "MFA"]) & (day["status"] != "OK")).sum()) if not day.empty else 0), None, sub="dernières 24 h")
    expired, limit = audit.retention_status()
    with k[3]:
        ui.kpi("Rétention", f"{AUDIT_RETENTION_YEARS} ans", None, sub=f"{expired} entrée(s) antérieure(s) au {limit:%d/%m/%Y}")
    if not ok:
        st.error(f"⛔ {msg} Une alerte de sécurité doit être ouverte.")
    else:
        st.success(msg, icon="🔐")

    sus = audit.suspicious_activity(df)
    if not sus.empty:
        st.warning("Comportements suspects détectés (24 h)", icon="⚠️")
        st.dataframe(sus, hide_index=True, width="stretch",
                     column_config={"user": "Utilisateur", "echecs_auth": "Échecs d'authentification", "exports": "Exports"})

    if df.empty:
        return
    ui.section("Événements")
    f = st.columns([1, 1, 1, 1.2])
    users = f[0].multiselect("Utilisateur", sorted(df["user"].unique()), placeholder="Tous")
    acts = f[1].multiselect("Action", sorted(df["action"].unique()), placeholder="Toutes")
    stat = f[2].multiselect("Statut", sorted(df["status"].unique()), placeholder="Tous")
    q = f[3].text_input("Recherche dans le détail")
    v = df.copy()
    if users:
        v = v[v["user"].isin(users)]
    if acts:
        v = v[v["action"].isin(acts)]
    if stat:
        v = v[v["status"].isin(stat)]
    if q:
        v = v[v["detail"].astype(str).str.contains(q, case=False, regex=False, na=False)]
    v = v.sort_values("seq", ascending=False)
    st.dataframe(v[["seq", "ts", "user", "role", "action", "status", "detail", "hash"]], hide_index=True,
                 width="stretch", height=420,
                 column_config={"seq": "N°", "ts": st.column_config.DatetimeColumn("Horodatage", format="DD/MM/YYYY HH:mm:ss"),
                                "user": "Utilisateur", "role": "Rôle", "action": "Action", "status": "Statut",
                                "detail": "Détail", "hash": st.column_config.TextColumn("Empreinte", width="small")})
    st.download_button("Exporter le journal (CSV)", v.to_csv(sep=";", index=False).encode("utf-8-sig"),
                       f"SASV_audit_{datetime.now():%Y%m%d_%H%M}.csv", "text/csv",
                       on_click=lambda: log("EXPORT_AUDIT", f"{len(v)} entrées"))


def page_admin():
    ui.hero("Administration des accès", "Comptes, rôles et périmètres selon le principe de moindre privilège.")
    users = security.list_users()
    rows = [{"Identifiant": l, "Nom": u["name"], "Rôle": ROLES[u["role"]]["label"],
             "Régions": ", ".join(u["regions"]) or "Toutes", "Familles": ", ".join(u["familles"]) or "Toutes",
             "Actif": u["active"],
             "Verrouillé": security.is_locked(u),
             "Dernière connexion": u["last_login"]} for l, u in users.items()]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")

    if S.get("_admin_msg"):
        st.success(S.pop("_admin_msg"))
    a, b = st.columns(2, gap="large")
    with a:
        ui.section("Créer un utilisateur")
        with st.form("new_user", clear_on_submit=True):
            login = st.text_input("Identifiant")
            name = st.text_input("Nom affiché")
            role = st.selectbox("Rôle", list(ROLES), format_func=lambda r: ROLES[r]["label"])
            regs = st.multiselect("Régions autorisées (vide = toutes)", data.REGIONS)
            fams = st.multiselect("Familles autorisées (vide = toutes)", data.FAMILLES)
            pwd = st.text_input("Mot de passe initial", type="password",
                                help="12 caractères minimum, majuscule, minuscule, chiffre et caractère spécial.")
            if st.form_submit_button("Créer le compte"):
                ok, msg = security.create_user((login or "").strip().lower(), pwd, role, name or login, regs, fams)
                log("ADMIN_CREATION_COMPTE", f"{login} ({role})", "OK" if ok else "ECHEC")
                if ok:
                    S["_admin_msg"] = msg
                    st.rerun()
                st.error(msg)
    with b:
        ui.section("Gérer un compte")
        target = st.selectbox("Compte", [l for l in users if l != S.login])
        if target:
            t = users[target]
            regs = st.multiselect("Régions", data.REGIONS, default=t["regions"], key=f"r_{target}")
            fams = st.multiselect("Familles", data.FAMILLES, default=t["familles"], key=f"f_{target}")
            c = st.columns(4 if security.is_locked(t) else 3)
            with c[0], st.container(key="black-a1"):
                if st.button("Mettre à jour le périmètre", width="stretch"):
                    security.update_perimeter(target, regs, fams)
                    log("ADMIN_PERIMETRE", f"{target} : régions={regs or 'toutes'}, familles={fams or 'toutes'}")
                    st.rerun()
            with c[1], st.container(key="black-a2"):
                lab = "Désactiver" if t["active"] else "Réactiver"
                if st.button(lab, width="stretch"):
                    security.set_active(target, not t["active"])
                    log("ADMIN_STATUT_COMPTE", f"{target} → {'inactif' if t['active'] else 'actif'}")
                    st.rerun()
            with c[2], st.container(key="black-a3"):
                if st.button("Réinitialiser le MFA", width="stretch"):
                    security.reset_mfa(target)
                    log("ADMIN_RESET_MFA", target)
                    st.success("Nouveau secret TOTP généré : l'utilisateur doit réenrôler son application.")
            if security.is_locked(t):
                with c[3], st.container(key="black-a4"):
                    if st.button("Déverrouiller", width="stretch"):
                        security.unlock(target)
                        log("ADMIN_DEVERROUILLAGE", target)
                        S["_admin_msg"] = f"Compte « {target} » déverrouillé."
                        st.rerun()


def audit_access_request(u):
    ui.section("Accès au journal d'audit")
    status = security.audit_request_status(u)
    if status == "accorde":
        st.success(f"Accès accordé jusqu'au {datetime.fromisoformat(u['audit_access_until']):%d/%m/%Y à %H:%M}. "
                   "La page **Audit** est disponible dans le menu.", icon="🔓")
    elif status == "en_attente":
        st.info(f"Demande envoyée le {datetime.fromisoformat(u['audit_request']['ts']):%d/%m/%Y à %H:%M}, "
                "en attente de validation par le Responsable sécurité.", icon="⏳")
    else:
        st.caption("Le journal d'audit est réservé au Responsable sécurité. En cas de nécessité, demandez un accès "
                   "temporaire : il vous sera accordé pour une durée limitée après validation.")
        with st.form("audit_req", clear_on_submit=True):
            motif = st.text_area("Motif de la demande", max_chars=500,
                                 placeholder="Ex. : vérification d'un export suspect signalé le 12/10.")
            if st.form_submit_button("Demander l'accès"):
                ok, msg = security.request_audit_access(S.login, motif)
                log("AUDIT_ACCES_DEMANDE", (motif or "").strip()[:200], "OK" if ok else "ECHEC")
                if ok:
                    st.rerun()
                st.error(msg)


def page_compte():
    u = user()
    ui.hero("Mon compte", "Sécurité de votre accès au SASV.", meta=f"{S.name} · {ROLES[S.role]['label']}")
    a, b = st.columns(2, gap="large")
    with a:
        ui.section("Profil et habilitations")
        st.markdown(f"**Identifiant :** {S.login}  \n**Rôle :** {ROLES[S.role]['label']}  \n"
                    f"**Périmètre :** {perimeter_label(u)}  \n"
                    f"**Session ouverte à :** {S.login_time:%H:%M} · expiration après {SESSION_TIMEOUT_MIN} min d'inactivité")
        ui.section("Changer de mot de passe")
        with st.form("pwd", clear_on_submit=True):
            old = st.text_input("Mot de passe actuel", type="password")
            new = st.text_input("Nouveau mot de passe", type="password",
                                help="12 caractères minimum, majuscule, minuscule, chiffre et caractère spécial.")
            new2 = st.text_input("Confirmer", type="password")
            if st.form_submit_button("Mettre à jour"):
                if new != new2:
                    st.error("Les deux saisies ne correspondent pas.")
                else:
                    ok, msg = security.change_password(S.login, old, new)
                    log("CHANGEMENT_MOT_DE_PASSE", "", "OK" if ok else "ECHEC")
                    (st.success if ok else st.error)(msg)
    with b:
        if ROLES[S.role].get("audit_on_request"):
            audit_access_request(u)
        ui.section("Double authentification (TOTP)")
        st.caption("Scannez ce QR code avec Google Authenticator, Microsoft Authenticator ou FreeOTP.")
        try:
            import qrcode
            img = qrcode.make(security.provisioning_uri(S.login), box_size=6, border=2)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            st.image(buf.getvalue(), width=220)
        except Exception:  # noqa: BLE001
            st.code(security.provisioning_uri(S.login))
        # Le contenu d'un st.expander s'exécute même replié : on n'affiche (et ne journalise) la clé que sur demande.
        if st.toggle("Afficher la clé pour une saisie manuelle", key="show_totp_secret"):
            if not S.get("_secret_logged"):
                log("CONSULTATION_SECRET_MFA", "Affichage de la clé TOTP")
                S["_secret_logged"] = True
            st.code(u["totp_secret"])
        else:
            S.pop("_secret_logged", None)


def page_aide():
    ui.hero("Aide et accompagnement", "Prendre en main le SASV selon votre profil.")
    faqs = {
        "Comment lire les variations ?": "Chaque indicateur est comparé à la **période précédente de même durée**. "
            "Exemple : pour « 30 derniers jours », la référence est les 30 jours qui précèdent.",
        "Pourquoi je ne vois pas toutes les régions ?": "Votre compte est limité à un **périmètre** (régions et/ou familles de produits) "
            "selon le principe de moindre privilège. Contactez la Direction pour toute extension.",
        "Comment déposer les ventes de mon agence ?": "Menu **Import** → téléchargez le modèle CSV, remplissez-le, puis déposez-le. "
            "Les lignes invalides sont listées avec leur motif de rejet ; seules les lignes valides sont intégrées.",
        "Que signifient les niveaux d'alerte ?": "**Moyenne** : seuil dépassé · **Élevée** : 1,4 × le seuil · **Critique** : 2 × le seuil. "
            "Les seuils sont paramétrables par la Direction et les managers.",
        "Mon compte est verrouillé": "Après 5 échecs, le compte est verrouillé 15 minutes. Un administrateur peut le déverrouiller immédiatement.",
        "Qui voit quoi ?": "**Agent de saisie** : dépôt des ventes de l'agence uniquement · **Chef d'agence** : tableau de bord, "
            "alertes, rapports et dépôts de son agence · **Direction Générale** : pilotage commercial ; le journal d'audit "
            "seulement sur autorisation temporaire · **Responsable sécurité** : journal d'audit · **Administrateur** : comptes et habilitations.",
        "Comment la Direction accède-t-elle au journal d'audit ?": "Menu **Mon compte** → *Demander l'accès* en précisant le motif. "
            "Le Responsable sécurité accorde un accès temporaire (1 h, 4 h ou 24 h) ; la page **Audit** apparaît alors "
            "dans le menu et disparaît automatiquement à expiration.",
        "J'ai changé de téléphone (MFA)": "Demandez à l'administrateur de **réinitialiser votre MFA**, puis scannez le nouveau QR code dans **Mon compte**.",
        "Mes actions sont-elles enregistrées ?": "Oui. Connexions, consultations, imports, exports et modifications sont inscrits dans un "
            "journal chaîné et signé, conservé 5 ans. Toute altération est détectée.",
    }
    for q, r in faqs.items():
        with st.expander(q):
            st.markdown(r)
    ui.section("Glossaire des indicateurs")
    st.markdown("""
| Indicateur | Définition |
|---|---|
| Chiffre d'affaires | Somme des montants TTC après remise (FCFA) |
| Transactions | Nombre de lignes de vente |
| Panier moyen | CA ÷ transactions |
| Taux de remise | Remises accordées ÷ CA brut avant remise |
| Projection fin de mois | CA du mois ÷ jours écoulés × jours du mois |
""")


# =============================================================================== navigation

if not S.auth:
    login_page()
    st.stop()

n_alerts = len(current_alerts()) if can("alertes") else 0
PAGE_DEFS = {
    "accueil": (page_accueil, "Accueil", ":material/home:"),
    "dashboard": (page_dashboard, "Tableau de bord", ":material/monitoring:"),
    "alertes": (page_alertes, f"Alertes ({n_alerts})" if n_alerts else "Alertes", ":material/notifications_active:"),
    "import": (page_import, "Import", ":material/upload_file:"),
    "rapports": (page_rapports, "Rapports", ":material/picture_as_pdf:"),
    "audit": (page_audit, "Audit", ":material/policy:"),
    "admin": (page_admin, "Administration", ":material/admin_panel_settings:"),
    "compte": (page_compte, "Mon compte", ":material/account_circle:"),
    "aide": (page_aide, "Aide", ":material/help:"),
}
PAGES = {k: st.Page(fn, title=t, icon=i, url_path=k, default=(k == "accueil"))
         for k, (fn, t, i) in PAGE_DEFS.items() if can(k)}

with st.sidebar:
    st.markdown(f"<div style='height:6px;background:{ui.HERO_GRADIENT};margin:-1rem -1rem 1rem'></div>",
                unsafe_allow_html=True)
    st.markdown("### SASV")
    st.caption(APP_FULL_NAME)
    st.markdown(f"**{html.escape(S.name)}**  \n<span class='pill'>{ROLES[S.role]['label']}</span>", unsafe_allow_html=True)
    u = user()
    st.caption(perimeter_label(u))
    st.caption(f"🔒 Session MFA · expire après {SESSION_TIMEOUT_MIN} min d'inactivité")
    if security.has_audit_grant(u) and S.role != "auditeur":
        st.caption(f"🔓 Accès audit jusqu'à {datetime.fromisoformat(u['audit_access_until']):%H:%M}")
    if S.role == "auditeur" and security.pending_audit_requests():
        st.markdown(f"<div style='font-size:.8rem'>⏳ <b>{len(security.pending_audit_requests())}</b> demande(s) "
                    "d'accès au journal à traiter</div>", unsafe_allow_html=True)
    with st.container(key="black-logout"):
        if st.button("Se déconnecter", width="stretch", icon=":material/logout:"):
            logout()
            st.rerun()
    if n_alerts:
        st.markdown(f"<div style='margin-top:1rem;font-size:.8rem'>🔔 <b>{n_alerts}</b> alerte(s) active(s) sur votre périmètre</div>",
                    unsafe_allow_html=True)

nav = st.navigation(list(PAGES.values()), position="top")
if S.get("_last_page") != nav.url_path:
    log("CONSULTATION", f"Page « {nav.title.split(' (')[0]} »")
    S["_last_page"] = nav.url_path
    S.pop("_last_filter", None)
    for k in ("_pdf", "_csv_ready", "_erp_ready"):
        S.pop(k, None)
nav.run()
