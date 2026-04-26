"""
SOC Analyst — Streamlit console (dark theme + API integration).
Run from package root: streamlit run streamlit_app.py
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict, Optional

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.api_client import APIClient, APIError
from utils.state import StateManager


def _soc_global_css() -> None:
    st.markdown(
        """
<style>
  .block-container { padding-top: 0.25rem !important; max-width: 100% !important; }
  header[data-testid="stHeader"] { background: transparent; }
  div[data-testid="stVerticalBlockBorderWrapper"] {
    border: 1px solid rgba(59, 130, 246, 0.18) !important;
    border-radius: 12px !important;
    box-shadow: 0 0 24px rgba(59, 130, 246, 0.06);
    background: linear-gradient(145deg, rgba(24, 24, 27, 0.85), rgba(9, 9, 11, 0.65)) !important;
    backdrop-filter: blur(10px);
  }
  .metric-threat-high [data-testid="stMetricValue"] { color: #ef4444 !important; }
  .metric-threat-mid [data-testid="stMetricValue"] { color: #f97316 !important; }
  .metric-threat-low [data-testid="stMetricValue"] { color: #22c55e !important; }
  .soc-panel-title { font-size: 0.75rem; letter-spacing: 0.08em; text-transform: uppercase; opacity: 0.7; }
</style>
""",
        unsafe_allow_html=True,
    )


MITRE_BY_ALERT: Dict[str, str] = {
    "brute_force": "T1110 — Brute Force",
    "malware_detected": "T1204 — User Execution",
    "impossible_travel": "T1078 — Valid Accounts",
}

SENDER_AVATAR: Dict[str, str] = {
    "supervisor": "🛡️",
    "log_hunter": "📋",
    "threat_intel": "🎯",
}


def _threat_display(score_0_1: float) -> tuple[str, str]:
    t = max(0.0, min(100.0, float(score_0_1) * 100.0))
    if t > 80:
        return f"{t:.0f}", "metric-threat-high"
    if t > 50:
        return f"{t:.0f}", "metric-threat-mid"
    return f"{t:.0f}", "metric-threat-low"


@st.cache_data(ttl=300)
def _cached_train_presets(api_base: str) -> Dict[str, Any]:
    client = APIClient(api_base, timeout_s=30.0, max_retries=2)
    return client.train_presets()


def _terminal_tab(client: APIClient, sm: StateManager) -> None:
    st.markdown('<p class="soc-panel-title">Incident console</p>', unsafe_allow_html=True)
    left, mid, right = st.columns([1, 2.1, 1.05], gap="small")

    with left:
        with st.container(border=True):
            st.caption("Session")
            diff = st.selectbox(
                "Difficulty",
                ["easy", "medium", "hard"],
                key="term_diff",
            )
            mode = st.selectbox(
                "Mode",
                ["multi_agent", "campaign", "single_agent"],
                key="term_mode",
            )
            c_r1, c_r2 = st.columns(2, gap="small")
            with c_r1:
                if st.button("Reset episode", use_container_width=True, type="secondary", key="btn_reset_ep"):
                    if sm.loading:
                        st.warning("Busy.")
                    else:
                        sm.loading = True
                        try:
                            r = client.multi_reset(difficulty=diff, mode=mode)
                            sm.clear_episode()
                            sm.episode_id = r.get("episode_id")
                            obs = r.get("observation") or {}
                            sm.last_observation = obs
                            if obs.get("transcript"):
                                sm.sync_transcript(obs.get("transcript", []))
                            sm.log(f"reset ok episode_id={sm.episode_id}")
                        except APIError as e:
                            sm.log(f"reset error: {e}")
                            st.error(str(e))
                        finally:
                            sm.loading = False
            with c_r2:
                st.caption("Episode")
                st.code(sm.episode_id or "—", language=None)

            st.divider()
            st.caption("Analyst quick actions (supervisor · take_action)")
            b1, b2, b3 = st.columns([1, 1, 1], gap="small")
            with b1:
                fp = st.button(
                    "🟢 False Positive",
                    use_container_width=True,
                    type="secondary",
                    key="act_fp",
                    disabled=not sm.episode_id or sm.loading,
                )
            with b2:
                es = st.button(
                    "🟡 Escalate Tier 2",
                    use_container_width=True,
                    type="secondary",
                    key="act_es",
                    disabled=not sm.episode_id or sm.loading,
                )
            with b3:
                bl = st.button(
                    "🔴 Block Malicious",
                    use_container_width=True,
                    type="primary",
                    key="act_bl",
                    disabled=not sm.episode_id or sm.loading,
                )
            for label, dec, fired in (
                ("false_positive", "false_positive", fp),
                ("escalate", "escalate_tier2", es),
                ("block", "block_if_malicious", bl),
            ):
                if fired and sm.episode_id and not sm.loading:
                    sm.loading = True
                    try:
                        r = client.multi_step(
                            episode_id=sm.episode_id,
                            action={
                                "action_type": "take_action",
                                "decision": dec,
                                "agent_role": "supervisor",
                                "reason": f"Analyst {label} (Streamlit UI)",
                                "confidence": 0.75,
                            },
                        )
                        obs = (r or {}).get("observation") or {}
                        sm.last_observation = obs
                        if obs.get("transcript"):
                            sm.sync_transcript(obs.get("transcript", []))
                        sm.log(f"action {label} reward={(r or {}).get('reward')}")
                    except APIError as e:
                        st.error(str(e))
                        if e.error_code == "INVALID_EPISODE":
                            sm.clear_episode()
                        sm.log(f"action error: {e}")
                    finally:
                        sm.loading = False

    with mid:
        with st.container(border=True):
            st.caption("Timeline (ID-addressable transcript · last 200 messages)")
            obs = sm.last_observation
            if obs and obs.get("transcript") is not None:
                sm.sync_transcript(obs.get("transcript", []))
            msgs = [m for _, m in sorted(sm.message_by_id.items(), key=lambda x: x[0])][-200:]
            if not msgs:
                st.info("Run **Reset episode** to start a multi-agent session, or use the API to populate state.")
            for m in msgs:
                sender = m.get("sender", "agent")
                av = SENDER_AVATAR.get(str(sender), "🤖")
                body = f"**{m.get('message_type', '')}** · conf={m.get('confidence', 0):.2f} · id={m.get('id', 0)}"
                with st.chat_message("assistant", avatar=av):
                    st.caption(f"{sender}")
                    st.markdown(body)
                    st.write(m.get("payload", ""))

    with right:
        with st.container(border=True):
            st.caption("SOC context")
            obs = sm.last_observation or {}
            alert = obs.get("alert_details") or {}
            atype = str(alert.get("type", "—"))
            ip = str(alert.get("ip", "—"))
            mitre = MITRE_BY_ALERT.get(alert.get("type", ""), "— (map in UI)")
            threat_num = 0.0
            mets: Optional[Dict[str, Any]] = None
            if sm.episode_id:
                try:
                    mets = client.eval_metrics(sm.episode_id)
                    raw = (mets or {}).get("metrics") or {}
                    threat_num = float(raw.get("last_validation_score", 0.0) or 0.0)
                except APIError as e:
                    st.warning(f"Metrics: {e}")
            val, tclass = _threat_display(threat_num)
            st.markdown(
                f'<div class="{tclass}">',
                unsafe_allow_html=True,
            )
            st.metric("Threat score (0–100)", val)
            st.markdown("</div>", unsafe_allow_html=True)
            st.metric("Source IP (alert)", "—" if ip == "None" else ip)
            st.text_area("MITRE (heuristic from alert type)", mitre, height=80, disabled=True, label_visibility="visible")
            st.caption("Alert type / id")
            st.write({"type": atype, "id": alert.get("id", "—")})

    st.divider()
    st.caption("Activity log (virtualized tail · last 100 lines)")
    for line in sm.log_slice(100):
        st.text(line)


def _integrations_tab(client: APIClient) -> None:
    st.subheader("Splunk")
    with st.form("splunk_form"):
        h = st.text_input("Host", value="127.0.0.1")
        p = st.number_input("Port", value=8089, min_value=1, max_value=65535)
        u = st.text_input("Username", value="admin")
        pw = st.text_input("Password", type="password")
        scheme = st.selectbox("Scheme", ["https", "http"])
        tcol, scol, ccol = st.columns([1, 1, 1])
        with tcol:
            test = st.form_submit_button("Test connection", use_container_width=True)
        with scol:
            save = st.form_submit_button("Save configuration", use_container_width=True, type="primary")
        with ccol:
            pass
        if test:
            try:
                r = client.test_splunk(h, int(p), u, pw, scheme)
                if r.get("ok"):
                    st.success(r.get("message", "OK"))
                else:
                    st.error(r.get("message", "Failed"))
            except APIError as e:
                st.error(str(e))
        if save:
            try:
                r = client.configure_splunk(h, int(p), u, pw, scheme)
                if r.get("ok"):
                    st.success(r.get("message", "OK"))
                else:
                    st.warning(r.get("message", "Not saved"))
            except APIError as e:
                st.error(str(e))


def _datasets_tab(client: APIClient) -> None:
    st.caption("Upload and explore uploaded logs (server-side in-memory store).")
    f = st.file_uploader("Log bundle", type=["log", "txt", "csv", "json", "jsonl"])
    if f is not None:
        if st.button("Upload", use_container_width=True, key="ds_upload"):
            data = f.getvalue()
            try:
                r, _ = client.upload_logs(data, f.name)
                st.success(r.get("message", "Uploaded"))
            except APIError as e:
                st.error(str(e))
    try:
        qcol, bcol = st.columns([4, 1], vertical_alignment="bottom")
    except TypeError:
        qcol, bcol = st.columns([4, 1])
    with qcol:
        q = st.text_input("Filter / search in uploaded logs", key="log_q")
    with bcol:
        go = st.button("Search", use_container_width=True, key="log_search_btn")
    if go:
        try:
            res = client.search_logs(q, max_results=200)
            rows = res.get("rows") or []
            st.caption(
                f"Rows: {res.get('count', 0)} · total uploaded: "
                f"{(res.get('summary') or {}).get('total_logs', '—')}"
            )
            if rows:
                df = pd.json_normalize(rows)
                st.dataframe(
                    df,
                    use_container_width=True,
                    height=400,
                )
            else:
                st.info("No rows. Upload logs first or change the query.")
        except APIError as e:
            st.error(str(e))


def _training_tab(client: APIClient, sm: StateManager) -> None:
    st.caption("Training loop status (server-side PPO / TRL). Presets are cached 5 min.")
    c1, c2, c3 = st.columns([1, 1, 1], gap="small")
    with c1:
        if st.button("Refresh presets", use_container_width=True, key="tr_refresh_presets"):
            st.cache_data.clear()
    with c2:
        st.metric("UI training state", sm.training_state)
    with c3:
        st.metric("Polls", sm.training_poll_count)

    try:
        presets = _cached_train_presets(client.api_base).get("presets") or {}
    except APIError as e:
        st.error(f"Presets: {e}")
        presets = {}

    choice = st.selectbox("Preset", list(presets.keys()) or ["(no presets)"])
    body = dict(presets.get(choice, {})) if choice in presets else {"episodes": 1, "model_name": "distilgpt2"}
    st.json(body)

    if st.button("Start training", use_container_width=True, type="primary", key="tr_start") and not sm.loading:
        sm.loading = True
        try:
            r = client.start_training(body)
            if r.get("ok") is False:
                st.error(r.get("message", "Failed"))
            else:
                sm.training_state = "running"
                st.session_state["saw_train_running"] = False
                st.success(r.get("message", "Started"))
        except APIError as e:
            st.error(str(e))
        finally:
            sm.loading = False

    try:
        status = client.training_status()
    except APIError as e:
        st.error(str(e))
        status = {}
    st.json(
        {k: status.get(k) for k in (
            "running", "completed_episodes", "total_episodes", "last_message", "model_name", "last_reward", "mode",
        )}
    )
    if bool(status.get("running")):
        st.session_state["saw_train_running"] = True
    if sm.training_state == "running" and st.session_state.get("saw_train_running") and not bool(
        status.get("running")
    ):
        sm.training_state = "completed"
    if int(st.session_state.get("training_poll_count", 0)) >= 100 and sm.training_state == "running":
        sm.training_state = "completed"

    try:
        rep = client.eval_report()
    except APIError as e:
        st.warning(f"Report: {e}")
        rep = {}
    history = rep.get("history") or []
    if history:
        chart = pd.DataFrame(
            {
                "episode": [h.get("episode") for h in history],
                "reward": [h.get("reward") for h in history],
            }
        )
        st.subheader("Episode rewards")
        st.line_chart(chart.set_index("episode"))
    else:
        st.caption("No `history` yet — run a training job with a working trainer.")


def main() -> None:
    st.set_page_config(
        page_title="SOC Analyst Console",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    _soc_global_css()
    sm = StateManager()
    if "api_base" not in st.session_state:
        st.session_state.api_base = os.environ.get("SOC_API_BASE", "http://127.0.0.1:7860")
    st.sidebar.text_input("API base URL", key="api_base")
    sm.api_base = st.session_state.api_base
    if sm.training_state == "running":
        poll_n = st_autorefresh(interval=2000, limit=100, key="soc_train_poll")
        st.session_state["training_poll_count"] = int(poll_n)
    else:
        st.session_state["training_poll_count"] = 0
    client = APIClient(sm.api_base)

    st.sidebar.caption("Heartbeat")
    try:
        h = client.health()
        st.sidebar.success("API OK" if h.get("ok") else "API reachable")
    except APIError as e:
        st.sidebar.error(str(e))
        h = {"ok": False}
    st.sidebar.caption("Trainer" if h.get("trainer_available") is True else h.get("trainer_error", "—"))

    tab_tr, tab_in, tab_ds, tab_train = st.tabs(
        ["🖥️ Terminal", "🔌 Integrations", "📂 Datasets", "🧠 Training"]
    )
    with tab_tr:
        _terminal_tab(client, sm)
    with tab_in:
        _integrations_tab(client)
    with tab_ds:
        _datasets_tab(client)
    with tab_train:
        _training_tab(client, sm)


if __name__ == "__main__":
    main()
