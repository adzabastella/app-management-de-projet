"""Charte graphique (reprise de la maquette) et composants d'interface."""
import html

import plotly.graph_objects as go
import streamlit as st

from .config import PURPLE, RED, ORANGE, CORAL, INK, MUTED, GRID

HERO_GRADIENT = "linear-gradient(112deg, #6E2C8F 0%, #9B2A5E 28%, #C3263A 55%, #C8282D 75%, #D9822B 100%)"

CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700;900&display=swap');

html, body, .stApp, .stMarkdown, .stMarkdown p, button p, input, textarea, label, h1, h2, h3, h4 {{
  font-family: 'Roboto', 'Helvetica Neue', Arial, sans-serif;
}}
.stApp {{ background: #F3F3F3; }}
.block-container {{
  max-width: 1180px; padding: 3.6rem 2rem 3rem;
  background: #FFFFFF; box-shadow: 0 0 24px rgba(0,0,0,.06);
}}
h1, h2, h3 {{ color: {INK}; letter-spacing: -.01em; }}
[data-testid="stSidebar"] {{ background: #FAFAFA; border-right: 1px solid #ECECEC; }}

/* ---------- Hero (bandeau dégradé de la maquette) ---------- */
.st-key-hero {{
  background: {HERO_GRADIENT};
  margin: 0 0 1.8rem 0; padding: 3.2rem 1.5rem 2.4rem; text-align: center;
  border-radius: 0; align-items: center;
}}
.st-key-hero * {{ text-align: center; }}
.st-key-hero [data-testid="stMarkdownContainer"] {{ width: 100%; }}
.st-key-hero > div {{ width: 100%; }}
.st-key-hero h1 {{ color: #fff; font-weight: 700; font-size: 2.15rem; margin: 0 0 .3rem; padding: 0; }}
.st-key-hero p {{ color: rgba(255,255,255,.92); font-weight: 300; font-size: 1.02rem; margin: 0; }}
.st-key-hero .hero-meta {{ font-size: .76rem; color: rgba(255,255,255,.82) !important; margin-top: .55rem; letter-spacing: .02em; }}
.st-key-hero [data-testid="stHorizontalBlock"] {{ justify-content: center; }}
.st-key-hero .stButton {{ display: flex; justify-content: center; }}
.st-key-hero .stButton button {{
  background: transparent; color: #fff; border: 1.5px solid rgba(255,255,255,.95);
  border-radius: 3px; font-size: .78rem; font-weight: 500; padding: .45rem 1.3rem; min-height: 0;
  width: auto !important; margin-top: 1.1rem;
}}
.st-key-hero .stElementContainer {{ width: 100%; }}
.st-key-hero .stButton button:hover {{ background: rgba(255,255,255,.14); color: #fff; border-color: #fff; }}

/* ---------- Cartes (Don Physique / Don Financier) ---------- */
[class*="st-key-card-"] {{
  background: #F7F7F7; box-shadow: 0 1px 4px rgba(0,0,0,.16); border-radius: 2px;
  padding: 0 0 1rem 0; gap: .35rem; overflow: hidden;
}}
.card-visual {{
  position: relative; height: 190px; background: #EEEEEE; overflow: hidden;
  display: flex; align-items: center; justify-content: center;
}}
.card-visual .arc {{
  position: absolute; border-radius: 50%; border: 22px solid {CORAL};
  box-shadow: 0 0 0 13px #FFFFFF;
}}
.card-visual .arc.tr {{ width: 190px; height: 190px; top: -105px; right: -105px; }}
.card-visual .arc.bl {{ width: 150px; height: 150px; bottom: -95px; left: -95px; }}
.card-visual .arc.lf {{ width: 260px; height: 260px; top: -35px; left: -215px; }}
.card-visual .word {{
  position: relative; z-index: 1; font-weight: 700; font-size: 1.85rem; line-height: 1.02;
  color: #3A3A3A; letter-spacing: -.02em; text-align: left;
}}
.card-visual .word span {{ color: {CORAL}; display: block; }}
.card-visual .word em {{ font-style: normal; display: block; }}
.card-body {{ padding: .9rem 1rem .9rem; min-height: 132px; }}
.card-body .t {{ font-weight: 700; font-size: .82rem; color: {INK}; margin-bottom: .35rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.card-body .v {{ white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.card-body .d {{ font-size: .74rem; color: #444; margin-bottom: .55rem; min-height: 2.6em; line-height: 1.35; }}
.card-body .v {{ font-weight: 700; font-size: 1rem; color: {INK}; }}
.card-body .delta {{ font-size: .72rem; font-weight: 500; margin-left: .35rem; }}
[class*="st-key-card-"] .stButton {{ padding: 0 1rem; }}
[class*="st-key-card-"] .stButton button, .st-key-black .stButton button,
[class*="st-key-black"] button, .stDownloadButton button, .stFormSubmitButton button {{
  background: #000; color: #fff; border: none; border-radius: 3px; font-size: .74rem; font-weight: 500;
  width: 100%; min-height: 2.2rem;
}}
[class*="st-key-card-"] .stButton button:hover, .stDownloadButton button:hover,
.stFormSubmitButton button:hover, [class*="st-key-black"] button:hover {{ background: #333; color: #fff; }}

/* ---------- Actualité ---------- */
.news-tile {{ height: 150px; border-radius: 1px; position: relative; overflow: hidden; }}
.news-tile.g {{ background: linear-gradient(135deg, #7A2E91 0%, #E0303A 55%, #F59B3B 82%, #FFD25E 100%); }}
.news-tile.p {{
  background:
    repeating-linear-gradient(45deg, #111 0 6px, #fff 6px 12px),
    #fff;
  -webkit-mask: none;
}}
.news-tile.p::after {{
  content: ""; position: absolute; inset: 0;
  background: repeating-linear-gradient(-45deg, rgba(255,255,255,.0) 0 6px, rgba(255,255,255,.55) 6px 12px);
}}
.news-tile.d {{ background: radial-gradient(circle at 55% 55%, #C3262F 0 22%, transparent 23%),
                         radial-gradient(circle at 40% 45%, #9E1F27 0 16%, transparent 17%), #1E1E1E; }}
.news-tile .badge {{
  position: absolute; z-index: 2; left: 10px; bottom: 10px; background: #fff; color: {INK};
  font-size: .68rem; font-weight: 700; padding: .2rem .5rem; border-radius: 2px; letter-spacing: .03em;
}}
.news-date {{ font-size: .7rem; color: {MUTED}; margin-top: .6rem; text-transform: uppercase; letter-spacing: .05em; }}
.news-title {{ font-weight: 700; font-size: .9rem; color: {INK}; margin: .15rem 0 .2rem; }}
.news-text {{ font-size: .8rem; color: #444; line-height: 1.4; }}

.section-title {{ font-weight: 700; font-size: 1.1rem; color: {INK}; margin: 1.8rem 0 .7rem; }}

/* ---------- KPI tiles (tableau de bord) ---------- */
.kpi {{ background: #F7F7F7; box-shadow: 0 1px 4px rgba(0,0,0,.14); padding: .9rem 1rem .8rem; border-top: 3px solid transparent;
        border-image: {HERO_GRADIENT} 1; min-height: 118px; }}
.kpi .l {{ font-size: .74rem; color: {MUTED}; font-weight: 500; text-transform: uppercase; letter-spacing: .04em; }}
.kpi .v {{ font-size: 1.45rem; font-weight: 700; color: {INK}; margin: .2rem 0 .1rem; white-space: nowrap; }}
.kpi .s {{ font-size: .74rem; color: {MUTED}; }}
.up {{ color: #15803D; font-weight: 600; }} .down {{ color: #B42318; font-weight: 600; }}

.alert-row {{ display: flex; gap: .8rem; padding: .7rem .9rem; background: #FAFAFA; border-left: 4px solid; margin-bottom: .45rem; }}
.alert-row .sev {{ font-size: .7rem; font-weight: 700; text-transform: uppercase; white-space: nowrap; min-width: 82px; }}
.alert-row .c {{ font-weight: 700; font-size: .86rem; color: {INK}; }}
.alert-row .m {{ font-size: .8rem; color: #444; }}

.pill {{ display: inline-block; font-size: .7rem; padding: .12rem .5rem; border-radius: 99px; background: #EFE7F4; color: {PURPLE}; font-weight: 600; margin-right: .25rem; }}
.secure-note {{ font-size: .74rem; color: {MUTED}; }}

/* ---------- Connexion ---------- */
.st-key-login-box {{ background: #fff; box-shadow: 0 1px 6px rgba(0,0,0,.16); padding: 1.4rem 1.6rem 1.2rem; }}
</style>
"""


def inject_css():
    st.markdown(CSS, unsafe_allow_html=True)


def hero(title: str, subtitle: str, meta: str = "", button: str | None = None, key: str = "hero_btn"):
    with st.container(key="hero"):
        st.markdown(f"<h1>{html.escape(title)}</h1><p>{html.escape(subtitle)}</p>"
                    + (f"<div class='hero-meta'>{html.escape(meta)}</div>" if meta else ""),
                    unsafe_allow_html=True)
        if button:
            return st.button(button, key=key)
    return False


def card(key: str, word1: str, word2: str, title: str, desc: str, value: str = "",
         delta: str = "", delta_cls: str = "", button: str = "En savoir +", variant: str = "a",
         accent_second: bool = True):
    """Carte au format de la maquette. variant 'a' = arcs coin haut-droit/bas-gauche, 'b' = arc gauche."""
    arcs = "<div class='arc tr'></div><div class='arc bl'></div>" if variant == "a" else \
           "<div class='arc lf'></div><div class='arc tr' style='opacity:.0'></div>"
    second = f"<span>{html.escape(word2)}</span>" if accent_second else f"<em>{html.escape(word2)}</em>"
    with st.container(key=f"card-{key}"):
        st.markdown(
            f"<div class='card-visual'>{arcs}<div class='word'>{html.escape(word1)}{second}</div></div>"
            f"<div class='card-body'><div class='t'>{html.escape(title)}</div><div class='d'>{html.escape(desc)}</div>"
            + (f"<div class='v'>{html.escape(value)}<span class='delta {delta_cls}'>{html.escape(delta)}</span></div>" if value else "")
            + "</div>",
            unsafe_allow_html=True)
        return st.button(button, key=f"btn-{key}", width="stretch")


def news(tile: str, badge: str, date: str, title: str, text: str):
    st.markdown(
        f"<div class='news-tile {tile}'><span class='badge'>{html.escape(badge)}</span></div>"
        f"<div class='news-date'>{html.escape(date)}</div><div class='news-title'>{html.escape(title)}</div>"
        f"<div class='news-text'>{html.escape(text)}</div>", unsafe_allow_html=True)


def kpi(label: str, value: str, delta: float | None = None, sub: str = "vs période préc.", invert=False):
    if delta is None:
        d = f"<span class='s'>{html.escape(sub)}</span>"
    else:
        good = (delta >= 0) != invert
        arrow = "▲" if delta >= 0 else "▼"
        d = f"<span class='{'up' if good else 'down'}'>{arrow} {delta:+.1f} %</span> <span class='s'>{html.escape(sub)}</span>"
    st.markdown(f"<div class='kpi'><div class='l'>{html.escape(label)}</div><div class='v'>{html.escape(value)}</div>{d}</div>",
                unsafe_allow_html=True)


def section(title: str):
    st.markdown(f"<div class='section-title'>{html.escape(title)}</div>", unsafe_allow_html=True)


def style_fig(fig: go.Figure, height: int = 340, legend: bool = True) -> go.Figure:
    fig.update_layout(
        height=height, margin=dict(l=8, r=12, t=36, b=8),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Roboto, sans-serif", size=12, color="#3A3A3A"),
        title_font=dict(size=14, color=INK), hoverlabel=dict(bgcolor="#fff", font_size=12, bordercolor="#ddd"),
        showlegend=legend,
        legend=dict(orientation="h", yanchor="bottom", y=1.0, xanchor="right", x=1, title=None, font_size=11),
        bargap=0.28,
    )
    fig.update_xaxes(showgrid=False, linecolor="#D0D0D0", ticks="", title=None)
    fig.update_yaxes(gridcolor=GRID, zeroline=False, linecolor="rgba(0,0,0,0)", title=None)
    return fig


SEQ = ["#F3E9F7", "#D9BCE6", "#B98AD0", "#9659B6", PURPLE, "#5A2C75"]
