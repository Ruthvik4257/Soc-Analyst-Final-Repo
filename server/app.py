import sys
import os
import asyncio
import csv
import json
import io
from datetime import datetime
from typing import Dict

# Add both parent directory and server directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

from openenv.core.env_server import create_fastapi_app
from fastapi import BackgroundTasks, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from environment import SocAnalystEnvironment
from models import SocAction, SocObservation
from server.datasets import (
    add_logs_from_content,
    clear_uploaded_logs,
    search_uploaded_logs,
    uploaded_logs_summary,
)
from server.integrations import SplunkClient, SplunkConfig, set_splunk_client
from server.threat_rules import rules_catalog, rules_status, update_rule_config, validate_decision

try:
    from server.rl_trainer import TRAINING_STATUS, get_training_logs, run_training_loop
    _trainer_import_error = ""
except Exception as exc:  # pragma: no cover - keeps API bootable when RL stack is unavailable
    _trainer_import_error = str(exc)

    class _FallbackStatus:
        running = False
        total_episodes = 0
        completed_episodes = 0
        last_reward = 0.0
        last_message = f"Trainer unavailable: {_trainer_import_error}"
        model_name = ""
        mode = "single_agent"
        run_seed = 42
        coordination_efficiency = 0.0
        evidence_sufficiency = 0.0
        recovery_after_mistake = 0.0
        memory_consistency_score = 0.0
        campaign_progress = 0.0
        delayed_reward_success_rate = 0.0
        per_agent_rewards = {"supervisor": 0.0, "log_hunter": 0.0, "threat_intel": 0.0}
        policy_mode = "single_policy"
        role_model_names = {"supervisor": "", "log_hunter": "", "threat_intel": ""}
        per_role_last_rewards = {"supervisor": 0.0, "log_hunter": 0.0, "threat_intel": 0.0}
        report_path = ""
        training_history = []
        training_logs = []

    TRAINING_STATUS = _FallbackStatus()

    def run_training_loop(*_args, **_kwargs):
        raise RuntimeError(f"RL trainer import failed: {_trainer_import_error}")

    def get_training_logs(*_args, **_kwargs):
        return []

app = create_fastapi_app(SocAnalystEnvironment, SocAction, SocObservation)
# Allow local file:// or separate dev ports to call the API if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
MULTI_AGENT_SESSIONS: Dict[str, SocAnalystEnvironment] = {}

TRAINING_PRESETS = {
    "run1_smoke": {
        "episodes": 2,
        "model_name": "distilgpt2",
        "learning_rate": 1e-5,
        "push_to_hub": False,
        "mode": "single_agent",
        "campaign_length": 20,
        "negotiation_rounds": 2,
        "seed": 42,
    },
    "run2_multi_agent": {
        "episodes": 5,
        "model_name": "distilgpt2",
        "learning_rate": 8e-6,
        "push_to_hub": False,
        "mode": "multi_agent",
        "campaign_length": 20,
        "negotiation_rounds": 2,
        "seed": 42,
    },
    "run3_campaign": {
        "episodes": 8,
        "model_name": "distilgpt2",
        "learning_rate": 5e-6,
        "push_to_hub": False,
        "mode": "campaign",
        "campaign_length": 30,
        "negotiation_rounds": 3,
        "seed": 42,
    },
}


@app.get("/")
def read_root():
    root_dir = os.path.dirname(os.path.dirname(__file__))
    return FileResponse(
        os.path.join(root_dir, "frontend", "index.html"),
        media_type="text/html",
    )


@app.post("/api/integrations/splunk")
def configure_splunk(config: SplunkConfig):
    try:
        client = SplunkClient(config)
        set_splunk_client(client)
        return {"ok": True, "message": "Splunk integration configured."}
    except Exception as exc:
        return {"ok": False, "message": f"Failed to configure Splunk: {exc}"}


@app.post("/api/integrations/splunk/test")
def test_splunk(config: SplunkConfig):
    try:
        client = SplunkClient(config)
        if client._service is None:
            return {
                "ok": False,
                "message": "Splunk SDK unavailable or could not build a service handle.",
            }
        # Lightweight server touch after connect
        _ = client._service.info
        return {"ok": True, "message": "Splunk connection test succeeded."}
    except Exception as exc:
        return {"ok": False, "message": f"Connection test failed: {exc}"}


# Default 2GB; nginx must also allow the body (see docker/nginx.conf.template client_max_body_size)
_MAX_UPLOAD = max(1, int(os.environ.get("MAX_UPLOAD_BYTES", str(2 * 1024 * 1024 * 1024))))


@app.post("/api/datasets/logs/upload")
async def upload_logs(file: UploadFile = File(...)):
    content = await file.read()
    n = len(content)
    if n > _MAX_UPLOAD:
        return JSONResponse(
            status_code=413,
            content={
                "ok": False,
                "message": f"File is {n} bytes; max is {_MAX_UPLOAD} bytes. Set env MAX_UPLOAD_BYTES to raise the limit (and match nginx).",
                "size_bytes": n,
                "max_bytes": _MAX_UPLOAD,
            },
        )
    inserted, warn = add_logs_from_content(file.filename or "uploaded.log", content)
    parts = [f"Received {n:,} bytes, added {inserted:,} log line(s) from {file.filename}."]
    if warn:
        parts.append(warn)
    return {
        "ok": True,
        "message": " ".join(parts),
        "size_bytes": n,
        "inserted": inserted,
        "warning": warn,
        "summary": uploaded_logs_summary(),
    }


@app.post("/api/datasets/logs/clear")
def clear_logs():
    clear_uploaded_logs()
    return {"ok": True, "message": "Uploaded logs cleared.", "summary": uploaded_logs_summary()}


@app.get("/api/datasets/logs/search")
def search_logs(query: str = "", max_results: int = 20):
    rows = search_uploaded_logs(query, max_results=max_results)
    return {"ok": True, "query": query, "count": len(rows), "rows": rows, "summary": uploaded_logs_summary()}


@app.get("/api/datasets/logs/summary")
def logs_summary():
    return {"ok": True, "summary": uploaded_logs_summary()}


@app.get("/api/datasets/summary")
def datasets_summary_alias():
    """Alias for clients that call /api/datasets/summary (same as /api/datasets/logs/summary)."""
    return {"ok": True, "summary": uploaded_logs_summary()}


@app.get("/api/rules/catalog")
def get_rules_catalog():
    return {"ok": True, "catalog": rules_catalog()}


@app.get("/api/rules/status")
def get_rules_status():
    return {"ok": True, "status": rules_status()}


@app.post("/api/rules/config")
def set_rules_config(payload: dict):
    updated = update_rule_config(payload or {})
    return {"ok": True, "config": updated}


@app.post("/api/rules/evaluate")
def evaluate_rules(payload: dict):
    payload = payload or {}
    query = (payload.get("query") or "").strip()
    max_results = int(payload.get("max_results", 200))
    alert = payload.get("alert") or {"type": "uploaded_dataset_evaluation"}
    logs = search_uploaded_logs(query, max_results=max_results)
    result = validate_decision(alert, logs)
    return {
        "ok": True,
        "query": query,
        "count": len(logs),
        "recommended_decision": result.recommended_decision,
        "severity": result.severity,
        "score": result.score,
        "confidence": result.confidence,
        "factors": result.factors,
        "rule_hits": result.rule_hits,
        "anomaly_signals": result.anomaly_signals,
        "ioc_hits": result.ioc_hits,
    }


_INVALID_EPISODE_BODY = {
    "error_code": "INVALID_EPISODE",
    "message": "Unknown episode_id",
}


def _invalid_episode_response():
    return JSONResponse(status_code=400, content=_INVALID_EPISODE_BODY)


@app.get("/healthz")
def healthz():
    return {
        "ok": True,
        "trainer_available": _trainer_import_error == "",
        "trainer_error": _trainer_import_error or None,
        "uploaded_logs": uploaded_logs_summary().get("total_logs", 0),
    }


@app.get("/api/health")
def api_health():
    return healthz()


@app.get("/api/train/presets")
def train_presets():
    return {"ok": True, "presets": TRAINING_PRESETS}


@app.post("/api/train")
def start_training(payload: dict, background_tasks: BackgroundTasks):
    if _trainer_import_error:
        return {"ok": False, "message": f"Training unavailable: {_trainer_import_error}"}
    if TRAINING_STATUS.running:
        return {"ok": False, "message": "Training already running."}
    episodes = int(payload.get("episodes", 1))
    model_name = payload.get("model_name")
    learning_rate = payload.get("learning_rate")
    push_to_hub = bool(payload.get("push_to_hub", False))
    mode = payload.get("mode", "single_agent")
    campaign_length = int(payload.get("campaign_length", 20))
    negotiation_rounds = int(payload.get("negotiation_rounds", 2))
    seed = int(payload.get("seed", 42))
    background_tasks.add_task(
        run_training_loop,
        episodes,
        model_name,
        learning_rate,
        push_to_hub,
        mode,
        campaign_length,
        negotiation_rounds,
        seed,
    )
    return {
        "ok": True,
        "message": f"Training started for {episodes} episodes.",
        "model_name": model_name or "distilgpt2",
        "mode": mode,
    }


@app.post("/api/multi/reset")
def multi_reset(payload: dict):
    difficulty = payload.get("difficulty", "easy")
    mode = payload.get("mode", "multi_agent")
    env = SocAnalystEnvironment()
    obs = env.reset(difficulty=difficulty, mode=mode)
    episode_id = env.state.episode_id
    MULTI_AGENT_SESSIONS[episode_id] = env
    return {"episode_id": episode_id, "observation": obs.model_dump()}


@app.post("/api/multi/step")
def multi_step(payload: dict):
    episode_id = payload.get("episode_id")
    action_payload = payload.get("action", {})
    if not episode_id or episode_id not in MULTI_AGENT_SESSIONS:
        return _invalid_episode_response()
    env = MULTI_AGENT_SESSIONS[episode_id]
    action = SocAction(**action_payload)
    obs = env.step(action)
    return {"ok": True, "episode_id": episode_id, "reward": obs.reward, "observation": obs.model_dump()}


@app.get("/api/eval/metrics")
def eval_metrics(episode_id: str):
    if not episode_id or episode_id not in MULTI_AGENT_SESSIONS:
        return _invalid_episode_response()
    env = MULTI_AGENT_SESSIONS[episode_id]
    metrics = env.state.episode_metrics.model_dump()
    return {"ok": True, "episode_id": episode_id, "mode": env.state.mode, "metrics": metrics}


@app.get("/api/train/status")
def training_status():
    return {
        "running": TRAINING_STATUS.running,
        "total_episodes": TRAINING_STATUS.total_episodes,
        "completed_episodes": TRAINING_STATUS.completed_episodes,
        "last_reward": TRAINING_STATUS.last_reward,
        "last_message": TRAINING_STATUS.last_message,
        "model_name": TRAINING_STATUS.model_name,
        "mode": TRAINING_STATUS.mode,
        "run_seed": TRAINING_STATUS.run_seed,
        "coordination_efficiency": TRAINING_STATUS.coordination_efficiency,
        "evidence_sufficiency": TRAINING_STATUS.evidence_sufficiency,
        "recovery_after_mistake": TRAINING_STATUS.recovery_after_mistake,
        "memory_consistency_score": TRAINING_STATUS.memory_consistency_score,
        "campaign_progress": TRAINING_STATUS.campaign_progress,
        "delayed_reward_success_rate": TRAINING_STATUS.delayed_reward_success_rate,
        "training_backend": TRAINING_STATUS.training_backend,
        "per_agent_rewards": TRAINING_STATUS.per_agent_rewards,
        "policy_mode": TRAINING_STATUS.policy_mode,
        "role_model_names": TRAINING_STATUS.role_model_names,
        "per_role_last_rewards": TRAINING_STATUS.per_role_last_rewards,
        "report_path": TRAINING_STATUS.report_path,
    }


@app.get("/api/train/logs")
def training_logs(offset: int = 0, limit: int = 200):
    logs = get_training_logs(offset=offset, limit=limit)
    return {
        "ok": True,
        "count": len(logs),
        "offset": max(0, int(offset)),
        "next_offset": max(0, int(offset)) + len(logs),
        "logs": logs,
    }


@app.get("/api/train/logs/download")
def download_training_logs():
    rows = getattr(TRAINING_STATUS, "training_logs", []) or []
    lines = []
    for entry in rows:
        ts_ms = int(entry.get("ts_ms", 0))
        level = str(entry.get("level", "info")).upper()
        message = str(entry.get("message", ""))
        payload = entry.get("payload") or {}
        payload_suffix = f" | {json.dumps(payload, ensure_ascii=True)}" if payload else ""
        lines.append(f"{ts_ms} [{level}] {message}{payload_suffix}")
    text = "\n".join(lines) if lines else "No training logs available.\n"
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    headers = {"Content-Disposition": f'attachment; filename="training_logs_{stamp}.txt"'}
    return PlainTextResponse(text, headers=headers)


@app.get("/api/train/logs/download.jsonl")
def download_training_logs_jsonl():
    rows = getattr(TRAINING_STATUS, "training_logs", []) or []
    if rows:
        content = "\n".join(json.dumps(row, ensure_ascii=True) for row in rows) + "\n"
    else:
        content = json.dumps({"message": "No training logs available."}, ensure_ascii=True) + "\n"
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    headers = {"Content-Disposition": f'attachment; filename="training_logs_{stamp}.jsonl"'}
    return PlainTextResponse(content, headers=headers, media_type="application/x-ndjson")


@app.get("/api/train/logs/download.csv")
def download_training_logs_csv():
    rows = getattr(TRAINING_STATUS, "training_logs", []) or []
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ts_ms", "level", "message", "payload_json"])
    for entry in rows:
        ts_ms = int(entry.get("ts_ms", 0))
        level = str(entry.get("level", "info"))
        message = str(entry.get("message", ""))
        payload = json.dumps(entry.get("payload") or {}, ensure_ascii=True)
        writer.writerow([ts_ms, level, message, payload])
    if not rows:
        writer.writerow([0, "info", "No training logs available.", "{}"])
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    headers = {"Content-Disposition": f'attachment; filename="training_logs_{stamp}.csv"'}
    return PlainTextResponse(output.getvalue(), headers=headers, media_type="text/csv")


@app.get("/api/train/logs/stream")
async def training_logs_stream(offset: int = 0):
    async def event_generator():
        cursor = max(0, int(offset))
        idle_heartbeats = 0
        while True:
            logs = get_training_logs(offset=cursor, limit=200)
            if logs:
                for entry in logs:
                    payload = json.dumps(entry, ensure_ascii=True)
                    yield f"event: log\ndata: {payload}\n\n"
                cursor += len(logs)
                idle_heartbeats = 0
                continue

            # Keep connection warm; stop once training is not running and no new logs.
            if not TRAINING_STATUS.running:
                yield "event: done\ndata: {}\n\n"
                break
            idle_heartbeats += 1
            if idle_heartbeats % 5 == 0:
                yield "event: heartbeat\ndata: {}\n\n"
            await asyncio.sleep(0.8)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/eval/report")
def eval_report():
    return {
        "ok": True,
        "mode": TRAINING_STATUS.mode,
        "model_name": TRAINING_STATUS.model_name,
        "episodes": TRAINING_STATUS.total_episodes,
        "completed_episodes": TRAINING_STATUS.completed_episodes,
        "coordination_efficiency": TRAINING_STATUS.coordination_efficiency,
        "evidence_sufficiency": TRAINING_STATUS.evidence_sufficiency,
        "recovery_after_mistake": TRAINING_STATUS.recovery_after_mistake,
        "memory_consistency_score": TRAINING_STATUS.memory_consistency_score,
        "campaign_progress": TRAINING_STATUS.campaign_progress,
        "delayed_reward_success_rate": TRAINING_STATUS.delayed_reward_success_rate,
        "training_backend": TRAINING_STATUS.training_backend,
        "per_agent_rewards": TRAINING_STATUS.per_agent_rewards,
        "policy_mode": TRAINING_STATUS.policy_mode,
        "role_model_names": TRAINING_STATUS.role_model_names,
        "per_role_last_rewards": TRAINING_STATUS.per_role_last_rewards,
        "history": TRAINING_STATUS.training_history,
        "report_path": TRAINING_STATUS.report_path,
    }


def main():
    import uvicorn
    uvicorn.run("server.app:app", host="0.0.0.0", port=8000, reload=True)

if __name__ == '__main__':
    main()


