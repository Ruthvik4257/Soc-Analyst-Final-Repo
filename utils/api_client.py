from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

import requests


class APIError(Exception):
    """Raised for normalized API and transport failures."""

    def __init__(
        self,
        message: str,
        *,
        error_code: Optional[str] = None,
        status_code: Optional[int] = None,
        raw: Any = None,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.status_code = status_code
        self.raw = raw


def _as_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except Exception:
        return None


def _normalize_error(response: requests.Response) -> None:
    data = _as_json(response)
    if response.status_code == 400 and isinstance(data, dict):
        code = data.get("error_code")
        if code:
            raise APIError(
                data.get("message") or response.text,
                error_code=code,
                status_code=400,
                raw=data,
            )
    if response.status_code >= 400:
        msg: str
        if isinstance(data, dict):
            msg = str(data.get("message") or data.get("detail") or response.text)
        else:
            msg = response.text or f"HTTP {response.status_code}"
        raise APIError(
            msg,
            error_code=None,
            status_code=response.status_code,
            raw=data,
        )


class APIClient:
    """
    HTTP client for the Soc Analyst FastAPI app with timeouts, light retries
    (GET/JSON-safe POST), and error normalization to APIError.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout_s: float = 60.0,
        max_retries: int = 3,
        retry_backoff_s: float = 0.4,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.max_retries = max(1, max_retries)
        self.retry_backoff_s = retry_backoff_s
        self._session = requests.Session()

    @property
    def api_base(self) -> str:
        return self.base_url

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Any = None,
        files: Any = None,
        data: Any = None,
        retry: bool = True,
    ) -> requests.Response:
        url = f"{self.base_url}{path}"
        last_err: Optional[Exception] = None
        attempts = self.max_retries if retry else 1
        for attempt in range(attempts):
            try:
                r = self._session.request(
                    method,
                    url,
                    json=json,
                    params=params,
                    files=files,
                    data=data,
                    timeout=self.timeout_s,
                )
                if r.status_code in (502, 503, 504) and attempt < attempts - 1:
                    time.sleep(self.retry_backoff_s * (2**attempt))
                    continue
                return r
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_err = exc
                if attempt < attempts - 1:
                    time.sleep(self.retry_backoff_s * (2**attempt))
                    continue
                raise APIError(
                    f"Request failed: {exc}",
                    error_code="TRANSPORT",
                    status_code=None,
                ) from exc
        if last_err:
            raise APIError(
                f"Request failed: {last_err}",
                error_code="TRANSPORT",
                status_code=None,
            ) from last_err
        raise APIError("Request failed: unknown", error_code="TRANSPORT", status_code=None)

    def _get_json(self, path: str, **kwargs: Any) -> Any:
        r = self._request("GET", path, **kwargs)
        if r.status_code >= 400:
            _normalize_error(r)
        if not r.content:
            return None
        data = _as_json(r)
        if data is None and r.text:
            return {"_text": r.text}
        return data

    def _post_json(self, path: str, payload: Any, **kwargs: Any) -> Any:
        r = self._request("POST", path, json=payload, **kwargs)
        if r.status_code >= 400:
            _normalize_error(r)
        if not r.content:
            return {"ok": True}
        return _as_json(r)

    def health(self) -> Dict[str, Any]:
        d = self._get_json("/healthz", retry=True)
        return d if isinstance(d, dict) else {"ok": False, "message": str(d)}

    def multi_reset(
        self, *, difficulty: str = "easy", mode: str = "multi_agent"
    ) -> Dict[str, Any]:
        return self._post_json(
            "/api/multi/reset", {"difficulty": difficulty, "mode": mode}
        )  # type: ignore[return-value]

    def multi_step(
        self, *, episode_id: str, action: Dict[str, Any]
    ) -> Dict[str, Any]:
        return self._post_json(
            "/api/multi/step", {"episode_id": episode_id, "action": action}
        )  # type: ignore[return-value]

    def eval_metrics(self, episode_id: str) -> Dict[str, Any]:
        d = self._get_json(
            "/api/eval/metrics", params={"episode_id": episode_id}
        )
        return d  # type: ignore[return-value]

    def configure_splunk(
        self, host: str, port: int, username: str, password: str, scheme: str
    ) -> Dict[str, Any]:
        return self._post_json(
            "/api/integrations/splunk",
            {
                "host": host,
                "port": port,
                "username": username,
                "password": password,
                "scheme": scheme,
            },
        )  # type: ignore[return-value]

    def test_splunk(
        self, host: str, port: int, username: str, password: str, scheme: str
    ) -> Dict[str, Any]:
        return self._post_json(
            "/api/integrations/splunk/test",
            {
                "host": host,
                "port": port,
                "username": username,
                "password": password,
                "scheme": scheme,
            },
        )  # type: ignore[return-value]

    def upload_logs(
        self, file_bytes: bytes, filename: str
    ) -> Tuple[Dict[str, Any], int]:
        url = f"{self.base_url}/api/datasets/logs/upload"
        last_err: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                r = self._session.post(
                    url,
                    files={"file": (filename, file_bytes)},
                    timeout=self.timeout_s * 2,
                )
                if r.status_code in (502, 503, 504) and attempt < self.max_retries - 1:
                    time.sleep(self.retry_backoff_s * (2**attempt))
                    continue
                if r.status_code >= 400:
                    _normalize_error(r)
                d = _as_json(r) or {}
                return (d, r.status_code)  # type: ignore[return-value]
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_err = exc
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_backoff_s * (2**attempt))
                    continue
                raise APIError(
                    f"upload failed: {exc}", error_code="TRANSPORT", status_code=None
                ) from exc
        raise APIError("upload failed", error_code="TRANSPORT", status_code=None)

    def search_logs(
        self, query: str = "", max_results: int = 200
    ) -> Dict[str, Any]:
        return self._get_json(
            "/api/datasets/logs/search",
            params={"query": query, "max_results": max_results},
        )  # type: ignore[return-value]

    def clear_logs(self) -> Dict[str, Any]:
        return self._post_json("/api/datasets/logs/clear", {})  # type: ignore[return-value]

    def train_presets(self) -> Dict[str, Any]:
        return self._get_json("/api/train/presets", retry=True)  # type: ignore[return-value]

    def start_training(self, body: Dict[str, Any]) -> Dict[str, Any]:
        r = self._request("POST", "/api/train", json=body, retry=False)
        if r.status_code >= 400:
            _normalize_error(r)
        return _as_json(r) or {}  # type: ignore[return-value]

    def training_status(self) -> Dict[str, Any]:
        return self._get_json("/api/train/status", retry=True)  # type: ignore[return-value]

    def eval_report(self) -> Dict[str, Any]:
        return self._get_json("/api/eval/report", retry=True)  # type: ignore[return-value]
