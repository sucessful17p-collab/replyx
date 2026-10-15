"""RelayChat X QR handoff portal for Streamlit Community Cloud.

This is a lightweight landing page only. Authentication, pairing approval,
chat messages, and sessions remain on the RelayChat FastAPI backend.
"""
from urllib.parse import urlencode
import streamlit as st

st.set_page_config(
    page_title="RelayChat X · Device linking",
    page_icon="🔗",
    layout="centered",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
      .block-container {max-width: 760px; padding-top: 3rem; padding-bottom: 3rem;}
      .hero {padding: 1.6rem; border: 1px solid rgba(128,128,128,.28); border-radius: 22px;}
      .eyebrow {font-size:.8rem; text-transform:uppercase; letter-spacing:.13em; opacity:.72;}
      .muted {opacity:.75; font-size:.94rem;}
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown('<div class="hero">', unsafe_allow_html=True)
st.markdown('<div class="eyebrow">RelayChat X · Device pairing</div>', unsafe_allow_html=True)
st.title("Link this device")
st.write("You're at the RelayChat device-linking portal. Continue to the official RelayChat server to sign in and approve this browser.")
st.markdown('</div>', unsafe_allow_html=True)

# Tokens are short-lived and are validated by the backend; the portal never stores them.
token = st.query_params.get("token", "")
if isinstance(token, list):
    token = token[0] if token else ""

backend = str(st.secrets.get("BACKEND_PUBLIC_URL", "")).strip().rstrip("/")
if not backend:
    st.error("The portal administrator has not configured BACKEND_PUBLIC_URL yet.")
    st.info("In Streamlit app settings, add BACKEND_PUBLIC_URL with the public HTTPS URL of your RelayChat backend.")
elif not backend.startswith("https://"):
    st.error("BACKEND_PUBLIC_URL must use HTTPS for a public deployment.")
elif not token or len(token) > 256 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for ch in token):
    st.warning("This QR link is missing a valid pairing token. Return to RelayChat on your desktop and generate a fresh QR code.")
    st.link_button("Open RelayChat", backend, use_container_width=True)
else:
    continue_url = f"{backend}/pair/scan?{urlencode({'token': token})}"
    st.success("QR link recognized. Pairing tokens expire after a short time.")
    st.link_button("Continue to RelayChat securely", continue_url, type="primary", use_container_width=True)
    st.caption("You'll sign in and approve the device on the RelayChat server. This portal does not ask for or store your password, OTP, or session cookie.")

st.divider()
st.markdown("**Having trouble?** Generate a new QR code from RelayChat and make sure the phone has internet access.")
st.markdown('<p class="muted">Independent project. Not affiliated with WhatsApp.</p>', unsafe_allow_html=True)
