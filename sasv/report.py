"""US-304 Export PDF du rapport de ventes ; E6 — export au format journal ERP."""
import hashlib
import io
from pathlib import Path
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
from fpdf import FPDF  # noqa: E402

from .config import PURPLE, RED, ORANGE, CANAL_COLORS  # noqa: E402
from .data import fmt_fcfa, fmt_int, fmt_date  # noqa: E402


FONT_DIR = Path(matplotlib.get_data_path()) / "fonts" / "ttf"   # DejaVu Sans, livrée avec matplotlib


def _ascii(s: str) -> str:
    return str(s)


def _gran(start, end):
    days = (pd.Timestamp(end) - pd.Timestamp(start)).days + 1
    return ("jour", "jour") if days <= 45 else (("semaine", "semaine") if days <= 200 else ("mois", "mois"))


def _chart_png(df: pd.DataFrame, gran: str) -> bytes:
    m = df.groupby([gran, "canal"], observed=True)["montant"].sum().unstack(fill_value=0)
    fig, ax = plt.subplots(figsize=(7.5, 2.8), dpi=160)
    for c in m.columns:
        ax.plot(m.index, m[c] / 1e6, color=CANAL_COLORS.get(c, PURPLE), lw=2, label=c)
    ax.set_ylabel("CA (M FCFA)", fontsize=8)
    ax.tick_params(labelsize=7)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.grid(axis="y", color="#ececec", lw=0.6)
    ax.legend(fontsize=7, frameon=False, ncol=3, loc="lower left", bbox_to_anchor=(0, 1.0))
    import matplotlib.dates as mdates
    ax.xaxis.set_major_locator(mdates.AutoDateLocator(maxticks=8))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%m/%Y" if gran == "mois" else "%d/%m"))
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    plt.close(fig)
    return buf.getvalue()


class _PDF(FPDF):
    def __init__(self, user, perimeter):
        super().__init__()
        self.user, self.perimeter = user, perimeter
        self.add_font("DejaVu", "", str(FONT_DIR / "DejaVuSans.ttf"))
        self.add_font("DejaVu", "B", str(FONT_DIR / "DejaVuSans-Bold.ttf"))

    def header(self):
        self.set_fill_color(122, 62, 157)
        self.rect(0, 0, 70, 3, "F")
        self.set_fill_color(214, 46, 63)
        self.rect(70, 0, 70, 3, "F")
        self.set_fill_color(232, 150, 58)
        self.rect(140, 0, 70, 3, "F")
        self.set_y(8)
        self.set_font("DejaVu", "B", 9)
        self.set_text_color(120)
        self.cell(0, 5, "SASV — Système Automatisé et Sécurisé de Suivi des Ventes", align="L")
        self.cell(0, 5, "CONFIDENTIEL — DIFFUSION RESTREINTE", align="R", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def footer(self):
        self.set_y(-14)
        self.set_font("DejaVu", "", 7)
        self.set_text_color(140)
        self.cell(0, 4, _ascii(f"Généré le {datetime.now():%d/%m/%Y %H:%M} par {self.user} — Périmètre : {self.perimeter}"), align="L")
        self.cell(0, 4, f"Page {self.page_no()}/{{nb}}", align="R")


def _table(pdf, df, widths, header_fill=(26, 26, 26)):
    pdf.set_font("DejaVu", "B", 8)
    pdf.set_fill_color(*header_fill)
    pdf.set_text_color(255)
    for col, w in zip(df.columns, widths):
        pdf.cell(w, 6, _ascii(col), border=0, fill=True, align="L" if w == widths[0] else "R")
    pdf.ln()
    pdf.set_font("DejaVu", "", 8)
    pdf.set_text_color(30)
    for i, row in enumerate(df.itertuples(index=False)):
        pdf.set_fill_color(*((245, 245, 245) if i % 2 else (255, 255, 255)))
        for v, w in zip(row, widths):
            pdf.cell(w, 5.5, _ascii(v), fill=True, align="L" if w == widths[0] else "R")
        pdf.ln()
    pdf.ln(3)


def build_pdf(df: pd.DataFrame, prev: pd.DataFrame, start, end, user: str, perimeter: str) -> bytes:
    pdf = _PDF(user, perimeter)
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(True, 18)
    pdf.add_page()
    pdf.set_font("DejaVu", "B", 18)
    pdf.set_text_color(26)
    pdf.cell(0, 10, "Rapport périodique des ventes", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("DejaVu", "", 10)
    pdf.set_text_color(90)
    pdf.cell(0, 6, _ascii(f"Période du {fmt_date(start)} au {fmt_date(end)}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    gran, gran_label = _gran(start, end)
    ca, ca_p = df["montant"].sum(), prev["montant"].sum()
    n, n_p = len(df), len(prev)
    kpis = [
        ("Chiffre d'affaires", fmt_fcfa(ca), ca, ca_p),
        ("Transactions", fmt_int(n), n, n_p),
        ("Panier moyen", fmt_fcfa(ca / n if n else 0), ca / n if n else 0, ca_p / n_p if n_p else 0),
        ("Articles vendus", fmt_int(df["qte"].sum()), df["qte"].sum(), prev["qte"].sum()),
    ]
    w = 45.5
    x0 = pdf.get_x()
    y0 = pdf.get_y()
    for i, (lab, val, a, b) in enumerate(kpis):
        x = x0 + i * (w + 2)
        pdf.set_fill_color(242, 242, 242)
        pdf.rect(x, y0, w, 22, "F")
        pdf.set_xy(x + 3, y0 + 2)
        pdf.set_font("DejaVu", "", 8)
        pdf.set_text_color(100)
        pdf.cell(w - 6, 4, _ascii(lab))
        pdf.set_xy(x + 3, y0 + 7)
        pdf.set_font("DejaVu", "B", 12)
        pdf.set_text_color(26)
        pdf.cell(w - 6, 7, _ascii(val))
        pdf.set_xy(x + 3, y0 + 15)
        pdf.set_font("DejaVu", "", 8)
        if b:
            d = (a / b - 1) * 100
            pdf.set_text_color(*((21, 128, 61) if d >= 0 else (180, 35, 24)))
            pdf.cell(w - 6, 4, f"{'+' if d >= 0 else ''}{d:.1f} % vs période préc.")
    pdf.set_xy(x0, y0 + 27)

    pdf.set_font("DejaVu", "B", 11)
    pdf.set_text_color(26)
    pdf.cell(0, 7, f"Évolution du CA par canal (par {gran_label})", new_x="LMARGIN", new_y="NEXT")
    pdf.image(io.BytesIO(_chart_png(df, gran)), w=185)
    pdf.ln(2)

    def section(title, frame, widths):
        if pdf.get_y() > 240:
            pdf.add_page()
        pdf.set_font("DejaVu", "B", 11)
        pdf.set_text_color(26)
        pdf.cell(0, 7, title, new_x="LMARGIN", new_y="NEXT")
        _table(pdf, frame, widths)

    def agg(col, top=None):
        g = df.groupby(col, observed=True).agg(ca=("montant", "sum"), tx=("ref", "count"), q=("qte", "sum"))
        gp = prev.groupby(col, observed=True)["montant"].sum()
        g["var"] = ((g["ca"] / gp - 1) * 100)
        g = g.sort_values("ca", ascending=False)
        if top:
            g = g.head(top)
        tot = df["montant"].sum() or 1
        return pd.DataFrame({
            col.replace("_", " ").capitalize(): g.index.astype(str),
            "CA (FCFA)": g["ca"].map(lambda v: fmt_int(v)),
            "Part": (g["ca"] / tot * 100).map(lambda v: f"{v:.1f} %"),
            "Transactions": g["tx"].map(fmt_int),
            "Var. vs préc.": g["var"].map(lambda v: "-" if pd.isna(v) else f"{v:+.1f} %"),
        })

    W = [55, 40, 25, 30, 35]
    section("CA par canal", agg("canal"), W)
    section("CA par région", agg("region"), W)
    section("CA par famille de produits", agg("famille"), W)
    section("Top 10 produits", agg("produit", 10), W)
    section("Points de vente", agg("point_vente"), W)

    return bytes(pdf.output())


def erp_journal(df: pd.DataFrame) -> tuple:
    """Journal des ventes agrégé (jour × point de vente × famille) + total de contrôle pour réconciliation."""
    j = (df.groupby([df["jour"].dt.strftime("%Y-%m-%d"), "point_vente", "famille"], observed=True)
         .agg(nb_lignes=("ref", "count"), qte=("qte", "sum"), montant_ttc=("montant", "sum"))
         .reset_index().rename(columns={"jour": "date_piece"}))
    j.insert(0, "journal", "VTE")
    j["compte"] = "701" + j["famille"].astype(str).str[:3].str.upper()
    csv = j.to_csv(sep=";", index=False).encode("utf-8")
    control = {"lignes": len(j), "total_ttc": int(j["montant_ttc"].sum()),
               "sha256": hashlib.sha256(csv).hexdigest()}
    return csv, control
