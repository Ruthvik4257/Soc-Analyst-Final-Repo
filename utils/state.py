from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import streamlit as st


class StateManager:
    """
    Centralized session state for the SOC Streamlit console.
    Avoids ad-hoc st.session_state keys scattered across the app.
    """

    _KEY = "_soc_state_mgr_inited_v1"

    def __init__(self) -> None:
        if st.session_state.get(self._KEY):
            return
        st.session_state[self._KEY] = True
        st.session_state["episode_id"] = None
        st.session_state["loading"] = False
        st.session_state["message_by_id"] = {}
        st.session_state["activity_logs"] = []
        st.session_state["training_state"] = "idle"
        st.session_state["training_poll_count"] = 0
        st.session_state["last_observation"] = None
        st.session_state.setdefault(
            "api_base", os.environ.get("SOC_API_BASE", "http://127.0.0.1:8000")
        )

    @property
    def episode_id(self) -> Optional[str]:
        return st.session_state.get("episode_id")  # type: ignore[return-value]

    @episode_id.setter
    def episode_id(self, value: Optional[str]) -> None:
        st.session_state.episode_id = value

    @property
    def loading(self) -> bool:
        return bool(st.session_state.get("loading"))

    @loading.setter
    def loading(self, v: bool) -> None:
        st.session_state.loading = v

    @property
    def message_by_id(self) -> Dict[int, Dict[str, Any]]:
        return st.session_state.message_by_id  # type: ignore[return-value]

    @property
    def activity_logs(self) -> List[str]:
        return st.session_state.activity_logs  # type: ignore[return-value]

    def log(self, line: str, *, cap: int = 500) -> None:
        st.session_state.activity_logs.append(line)
        st.session_state.activity_logs = st.session_state.activity_logs[-cap:]

    @property
    def training_state(self) -> str:
        return str(st.session_state.get("training_state", "idle"))

    @training_state.setter
    def training_state(self, v: str) -> None:
        st.session_state.training_state = v

    @property
    def training_poll_count(self) -> int:
        return int(st.session_state.get("training_poll_count", 0))

    @training_poll_count.setter
    def training_poll_count(self, v: int) -> None:
        st.session_state.training_poll_count = v

    @property
    def last_observation(self) -> Optional[Dict[str, Any]]:
        return st.session_state.get("last_observation")  # type: ignore[return-value]

    @last_observation.setter
    def last_observation(self, o: Optional[Dict[str, Any]]) -> None:
        st.session_state.last_observation = o

    @property
    def api_base(self) -> str:
        """Read-only: value comes from the sidebar `text_input` with key ``api_base``."""
        return str(st.session_state.get("api_base", "http://127.0.0.1:8000")).rstrip("/")

    def sync_transcript(
        self, transcript: List[Dict[str, Any]], cap: int = 5000
    ) -> None:
        for m in transcript or []:
            mid = m.get("id")
            if isinstance(mid, int) and mid > 0:
                st.session_state.message_by_id[mid] = m
        # cap dict size
        d = st.session_state.message_by_id
        if len(d) > cap:
            for k in sorted(d.keys())[: max(0, len(d) - cap)]:
                d.pop(k, None)

    def clear_episode(self) -> None:
        st.session_state.message_by_id = {}
        st.session_state.last_observation = None
        st.session_state.episode_id = None

    def log_slice(self, n: int = 100) -> List[str]:
        rows = st.session_state.activity_logs
        return rows[-n:] if n else rows
