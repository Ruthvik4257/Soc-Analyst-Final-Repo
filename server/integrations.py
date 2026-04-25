from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

try:
    import splunklib.client as splunk_client
except Exception:  # pragma: no cover - optional dependency at runtime
    splunk_client = None

try:
    import paramiko
except Exception:  # pragma: no cover - optional dependency at runtime
    paramiko = None

try:
    from mcp.server import Server
except Exception:  # pragma: no cover - fallback keeps imports safe
    class Server:  # type: ignore[override]
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self.tools: Dict[str, Any] = {}

        def tool(self, *_args: Any, **_kwargs: Any):
            def _decorator(func):
                self.tools[func.__name__] = func
                return func

            return _decorator


class SplunkConfig(BaseModel):
    host: str
    port: int = Field(default=8089)
    username: str
    password: str
    scheme: str = Field(default="https")


class SplunkClient:
    def __init__(self, config: SplunkConfig) -> None:
        self.config = config
        self._service = None
        if splunk_client is not None:
            self._service = splunk_client.connect(
                host=config.host,
                port=config.port,
                username=config.username,
                password=config.password,
                scheme=config.scheme,
            )

    def search(self, query: str, max_results: int = 50) -> List[Dict[str, Any]]:
        # Real query path when splunk-sdk is available.
        if self._service is not None:
            jobs = self._service.jobs
            search_query = query if query.strip().startswith("search") else f"search {query}"
            job = jobs.create(search_query)
            while not job.is_done():
                pass
            rows: List[Dict[str, Any]] = []
            for result in job.results(output_mode="json"):
                if isinstance(result, dict):
                    rows.append(result)
                if len(rows) >= max_results:
                    break
            return rows

        # Fallback mock result if SDK is not present yet.
        return [{"_raw": f"mock_splunk_result for query={query}"}]


class VMConfig(BaseModel):
    host: str
    port: int = Field(default=22)
    username: str
    password: Optional[str] = None
    key_path: Optional[str] = None


class VMConnector:
    def __init__(self, config: VMConfig) -> None:
        self.config = config
        self._client = None
        if paramiko is not None:
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_kwargs: Dict[str, Any] = {
                "hostname": config.host,
                "port": config.port,
                "username": config.username,
            }
            if config.key_path:
                connect_kwargs["key_filename"] = config.key_path
            else:
                connect_kwargs["password"] = config.password
            self._client.connect(**connect_kwargs)

    def run_command(self, command: str) -> str:
        if self._client is None:
            return f"mock_vm_output for command={command}"
        stdin, stdout, stderr = self._client.exec_command(command)
        _ = stdin
        err = stderr.read().decode("utf-8", errors="ignore").strip()
        out = stdout.read().decode("utf-8", errors="ignore").strip()
        return out if out else err


mcp_server = Server("soc-integrations")
_splunk_client: Optional[SplunkClient] = None

if hasattr(mcp_server, "tool"):
    _mcp_tool = mcp_server.tool
else:
    def _mcp_tool(*_args: Any, **_kwargs: Any):
        def _decorator(func):
            return func
        return _decorator


def set_splunk_client(client: SplunkClient) -> None:
    global _splunk_client
    _splunk_client = client


def get_splunk_client() -> Optional[SplunkClient]:
    return _splunk_client


@_mcp_tool()
def execute_spl(query: str) -> List[Dict[str, Any]]:
    if _splunk_client is None:
        return [{"error": "Splunk client not initialized"}]
    return _splunk_client.search(query)
