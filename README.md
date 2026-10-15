# RelayChat X — Streamlit QR Pairing Portal

A small companion landing page for QR device linking. It is intentionally separate from the FastAPI app: Streamlit Community Cloud hosts this portal, while the RelayChat backend handles authentication, pairing status, sessions, messages and WebSockets.

## Deploy to Streamlit Community Cloud

1. Push the parent `relaychat-x` repository to GitHub.
2. In Streamlit Community Cloud, create an app from that repository.
3. Set **Main file path** to `streamlit-pair-portal/app.py`.
4. In app Settings → Secrets, add:

   ```toml
   BACKEND_PUBLIC_URL = "https://YOUR-PUBLIC-RELAYCHAT-BACKEND"
   ```

5. Deploy. Copy the resulting `https://....streamlit.app` URL.

## Configure the RelayChat backend

Set these variables in the backend deployment's environment (do not commit credentials):

```dotenv
APP_BASE_URL=https://YOUR-PUBLIC-RELAYCHAT-BACKEND
PAIR_BASE_URL=https://YOUR-STREAMLIT-APP.streamlit.app
PAIR_SCAN_PATH=
COOKIE_SECURE=true
WEBAUTHN_RP_ID=YOUR-PUBLIC-RELAYCHAT-BACKEND-HOSTNAME
```

`WEBAUTHN_RP_ID` is the hostname only, without `https://` or a path. `PAIR_SCAN_PATH` must be an empty value so QR codes open the Streamlit app root with `?token=...`. Restart/redeploy the backend after changing variables.

## How the flow works

1. RelayChat backend creates a short-lived, random pairing token.
2. The desktop QR points to this Streamlit app with the token in the query string.
3. Streamlit provides a link to the backend's `/pair/scan?token=...` route.
4. The backend validates expiry and state, handles sign-in and approval, and completes the pairing.

The Streamlit app does not receive passwords or cookies and does not store tokens. The token is a temporary bearer value; do not log it or share screenshots of active QR codes. A QR portal alone does not make a private/local backend reachable from the internet.
