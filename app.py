import os
import urllib.parse
from typing import Dict, List, Optional

import streamlit as st
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]
TOKEN_FILE = "token.json"


def set_page() -> None:
    st.set_page_config(page_title="Gmail Read-Only Login", layout="centered")
    st.title("Sign in with Google (Gmail Read-Only)")


def get_saved_credentials() -> Optional[Credentials]:
    if not os.path.exists(TOKEN_FILE):
        return None
    try:
        return Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    except Exception:
        return None


def refresh_if_needed(creds: Credentials) -> Optional[Credentials]:
    if creds and creds.valid:
        return creds
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            with open(TOKEN_FILE, "w", encoding="utf-8") as f:
                f.write(creds.to_json())
            return creds
        except Exception as e:
            st.warning(f"Token refresh failed: {e}")
    return None


def load_secrets() -> Optional[Dict]:
    web = st.secrets.get("web")
    auth_cfg = st.secrets.get("auth")
    if not web or not auth_cfg:
        st.error("Missing [web] or [auth] in .streamlit/secrets.toml")
        return None
    return {"web": web, "auth": auth_cfg}


def client_config_from_secrets(s: Dict) -> Dict:
    web, auth_cfg = s["web"], s["auth"]
    return {
        "web": {
            "client_id": web.get("client_id"),
            "project_id": web.get("project_id"),
            "auth_uri": web.get("auth_uri"),
            "token_uri": web.get("token_uri"),
            "auth_provider_x509_cert_url": web.get("auth_provider_x509_cert_url"),
            "client_secret": web.get("client_secret"),
            "redirect_uris": [auth_cfg.get("redirect_uri")],
            "javascript_origins": [],
        }
    }


def ensure_flow_in_state(cfg: Dict, redirect_uri: str, flow_key: str, url_key: str) -> None:
    if flow_key in st.session_state:
        return
    st.session_state[flow_key] = Flow.from_client_config(cfg, scopes=SCOPES, redirect_uri=redirect_uri)
    auth_url, _ = st.session_state[flow_key].authorization_url(
        access_type="offline", include_granted_scopes="true", prompt="consent"
    )
    st.session_state[url_key] = auth_url


def query_params() -> Dict[str, str]:
    try:
        params = st.query_params if hasattr(st, "query_params") else st.experimental_get_query_params()
    except Exception:
        params = {}
    if isinstance(params, dict):
        return {k: (v if isinstance(v, str) else v[0]) for k, v in params.items()}
    return {}


def clear_query() -> None:
    try:
        if hasattr(st, "query_params"):
            st.query_params.clear()
        else:
            st.experimental_set_query_params()
    except Exception:
        pass


def save_creds_from_flow(flow_key: str) -> Credentials:
    creds = st.session_state[flow_key].credentials
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        f.write(creds.to_json())
    return creds


def finalize_auth(flow_key: str, url_key: str) -> None:
    for k in (flow_key, url_key):
        if k in st.session_state:
            del st.session_state[k]
    clear_query()
    st.success("Authorized. Read-only Gmail access granted and saved.")
    st.rerun()


def auto_complete_if_code(flow_key: str, url_key: str, redirect_uri: str) -> bool:
    params = query_params()
    code = params.get("code")
    if not code:
        return False
    st.info("Completing sign-in…")
    try:
        q = urllib.parse.urlencode(params)
        auth_response_url = f"{redirect_uri}?{q}"
        st.session_state[flow_key].fetch_token(authorization_response=auth_response_url)
    except Exception:
        st.session_state[flow_key].fetch_token(code=code)
    save_creds_from_flow(flow_key)
    finalize_auth(flow_key, url_key)
    return True


def manual_completion_ui(flow_key: str, url_key: str) -> None:
    st.info("2) If not redirected, paste full URL or just the code.")
    user_input = st.text_input("Redirect URL or code")
    if st.button("Complete Sign-in") and user_input:
        if user_input.startswith("http"):
            st.session_state[flow_key].fetch_token(authorization_response=user_input)
        else:
            st.session_state[flow_key].fetch_token(code=user_input)
        save_creds_from_flow(flow_key)
        finalize_auth(flow_key, url_key)


def auth_ui() -> Optional[Credentials]:
    s = load_secrets()
    if not s:
        return None
    cfg = client_config_from_secrets(s)
    redirect_uri = s["auth"].get("redirect_uri")
    flow_key, url_key = "oauth_flow", "oauth_auth_url"
    ensure_flow_in_state(cfg, redirect_uri, flow_key, url_key)
    st.markdown(f"[Authorize with Google]({st.session_state[url_key]})", unsafe_allow_html=True)
    if auto_complete_if_code(flow_key, url_key, redirect_uri):
        return None
    manual_completion_ui(flow_key, url_key)
    return None


def gmail_service(creds: Credentials):
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def list_message_ids(service, query: str, limit: int) -> List[str]:
    ids, token = [], None
    while len(ids) < limit:
        resp = (
            service.users()
            .messages()
            .list(userId="me", q=query, maxResults=min(100, limit - len(ids)), pageToken=token)
            .execute()
        )
        ids.extend([m["id"] for m in resp.get("messages", [])])
        token = resp.get("nextPageToken")
        if not token or not resp.get("messages"):
            break
    return ids[:limit]


def fetch_metadata(service, msg_id: str) -> Dict[str, str]:
    msg = (
        service.users()
        .messages()
        .get(userId="me", id=msg_id, format="metadata", metadataHeaders=["From", "To", "Subject", "Date"])
        .execute()
    )
    headers = {h["name"]: h.get("value", "") for h in msg.get("payload", {}).get("headers", [])}
    return {
        "Subject": headers.get("Subject", ""),
        "From": headers.get("From", ""),
        "Date": headers.get("Date", ""),
        "Snippet": msg.get("snippet", ""),
        "Message ID": msg.get("id", ""),
        "Thread ID": msg.get("threadId", ""),
    }


def gmail_search(creds: Credentials, query: str, limit: int) -> List[Dict[str, str]]:
    try:
        svc = gmail_service(creds)
        ids = list_message_ids(svc, query, limit)
        return [fetch_metadata(svc, i) for i in ids]
    except HttpError as e:
        raise RuntimeError(f"Gmail API error: {e}")


def reset_auth_ui() -> None:
    with st.expander("Reset authorization", expanded=False):
        if st.button("Reset now"):
            try:
                if os.path.exists(TOKEN_FILE):
                    os.remove(TOKEN_FILE)
                st.info("Removed saved credentials. Please sign in again.")
                st.rerun()
            except Exception as e:
                st.error(f"Failed to remove token: {e}")


def search_ui(creds: Credentials) -> None:
    st.subheader("Search Gmail")
    q = st.text_input("Gmail search query", value="in:inbox newer_than:7d")
    limit = st.slider("Max results", min_value=5, max_value=200, value=25, step=5)
    col1, col2 = st.columns([1, 1])
    with col1:
        run = st.button("Search")
    with col2:
        if q:
            url = f"https://mail.google.com/mail/u/0/#search/{urllib.parse.quote(q)}"
            st.link_button("Open in Gmail", url=url)
    if run and q:
        with st.spinner("Searching Gmail..."):
            rows = gmail_search(creds, q, limit)
            if not rows:
                st.info("No messages found.")
            else:
                st.write(f"Found {len(rows)} message(s).")
                st.dataframe(rows, use_container_width=True)


def main() -> None:
    set_page()
    creds = get_saved_credentials()
    creds = refresh_if_needed(creds) if creds else None
    if creds and creds.valid:
        st.success("Authorized for Gmail read-only.")
        reset_auth_ui()
        search_ui(creds)
        return
    st.info("Sign in to grant read-only access to your Gmail.")
    auth_ui()


if __name__ == "__main__":
    main()
