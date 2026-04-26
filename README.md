---
title: Soc Analyst Final Repo
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: docker
pinned: false
---

# SOC Analyst Incident Triage Environment

A real-world OpenEnv environment where an AI agent acts as a Tier 1 Security Operations Center (SOC) analyst. The agent triages incoming security alerts by gathering evidence from logs, threat intelligence, and asset context before making a final resolution.

## Task Details
The environment provides 3 tasks simulating real-world alerts:
1. **Easy**: Brute force login attempt.
2. **Medium**: Critical malware infection.
3. **Hard**: Impossible travel alert (VPN exit node false positive).

## Actions
The agent can query internal tools using:
- `search_logs`
- `get_threat_intel`
- `get_asset_info`
- `take_action` (`false_positive`, `escalate_tier2`, `block_if_malicious`)

## Grading & Rewards
- Partial rewards are issued for useful evidence gathering.
- Final score depends on resolution correctness and evidence sufficiency.

## Files Overview
- `models.py`: Typed schemas for actions, observations, and multi-agent metrics.
- `server/environment.py`: Single-agent, multi-agent, and campaign environment logic.
- `server/rl_trainer.py`: PPO training loop and training report generation.
- `server/app.py`: API routes for environment interaction, training, and metrics.
- `frontend/index.html`: Basic web console (HTML/CSS/JS) for Terminal, Integrations, Datasets, and Training; served at `/` by FastAPI.
- `docker/entrypoint.sh`, `docker/nginx.conf.template`: Nginx in the Space forwards the public `PORT` to FastAPI (same process serves `/`, `/api/`, `/docs`, `/healthz`, OpenEnv routes, etc.).

## Usage
1. Provide credentials if needed:
   ```bash
   export OPENAI_API_KEY="your_api_key_here"
   export MODEL_NAME="gpt-4o"
   ```
2. Run baseline inference:
   ```bash
   python inference.py
   ```

## Run the web console on your PC (Windows)

- Double-click **`run_local.cmd`**, or run **`.\run_local.ps1`**. A window opens with **Uvicorn**; open [http://127.0.0.1:8000](http://127.0.0.1:8000) for the HTML console (API docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)). The first start can take 1–2 minutes while the stack loads.
- Or: `uvicorn server.app:app --host 127.0.0.1 --port 8000` from the project root with `PYTHONPATH` set to that root.
- If you host the static page elsewhere, set the **API base** field in the sidebar to your API’s URL (CORS is enabled for development).

## Google Colab

1. Open the notebook **`notebooks/SocAnalyst_Colab.ipynb`** in Colab: from [this Space repo](https://huggingface.co/spaces/Suryaai05/Soc-Analyst-Final-Repo) use **Open in Colab** if linked, or **File → Upload notebook** after [downloading the file from the `notebooks` folder](https://huggingface.co/spaces/Suryaai05/Soc-Analyst-Final-Repo/tree/main/notebooks), or paste the raw Git URL in Colab **File → Open notebook → GitHub** using your fork or the Space’s Git URL.
2. **Runtime → Change runtime type** → set **T4 or A100 GPU** if you will run PPO training (optional for API-only).
3. Run the cells in order: **clone** (edit `REPO_URL` if needed) → **pip install** → **start Uvicorn** and wait until `/healthz` succeeds (first start can take several minutes).
4. Run the **API** cell: it calls `GET /api/datasets/summary` and `POST /api/train` on `http://127.0.0.1:8000` inside the same Colab session.
5. (Optional) Add Colab **Secrets** `NGROK_AUTH_TOKEN` and run the **ngrok** cell for a public URL to the web UI and `/docs`.

## Hugging Face Space Deployment

This repository is configured as a Docker Space (`sdk: docker`).

The container exposes a **single public port** (`PORT`, default **7860**). **nginx** forwards it to **FastAPI** (127.0.0.1:8000), which serves **`/`** (HTML console), **`/api/*`**, **`/healthz`**, **`/docs`**, OpenEnv routes (**`/reset`**, **`/step`**, …), **`/mcp`**, **`/ws`**, etc.

Init uses **tini** so child processes are reaped. First boot can take **several minutes** on CPU while PyTorch and the app import; the entrypoint waits up to ~5 minutes for `GET /healthz` before starting nginx.

**Large log uploads:** nginx is configured for **up to ~2GB** per request (`client_max_body_size`). The API will reject bodies over **`MAX_UPLOAD_BYTES`** (default 2GB). Ingested lines are capped at **`MAX_LOG_ENTRIES`** (default 500,000) per file to protect RAM. After upload, use **Datasets → Search** with an empty query to list the first 200 lines, or a keyword to filter.

### 1) Push this repo to a Hugging Face Space
- Create a Space.
- Choose **Docker** SDK.
- Push this project contents.

### 2) Configure Space secrets
Set in **Space Settings -> Variables and secrets**:
- `HF_TOKEN` (required to push trained checkpoints to Hub)
- `HF_REPO_ID` (for example: `username/soc-ppo-agent`)
- `HF_MODEL_NAME` (optional, default: `distilgpt2`)
- `TRAIN_LR` (optional, default: `1e-5`)
- `TRAIN_OUTPUT_DIR` (optional, default: `./artifacts/ppo-soc-model`)
- `SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_USERNAME`, `SPLUNK_PASSWORD`, `SPLUNK_SCHEME` (optional)

### 3) Training API payload for TRL PPO
Call `POST /api/train` with:
```json
{
  "episodes": 10,
  "model_name": "distilgpt2",
  "learning_rate": 1e-5,
  "push_to_hub": true,
  "mode": "multi_agent",
  "campaign_length": 20,
  "negotiation_rounds": 2,
  "seed": 42
}
```

Check progress:
- `GET /api/train/status`
- `GET /api/eval/report`

Milestone-3 campaign metrics exposed in status/report:
- `recovery_after_mistake`
- `memory_consistency_score`
- `campaign_progress`
- `delayed_reward_success_rate`

### 4) Notes for HF compute credits
- Prefer **GPU Space hardware** for PPO training.
- Start with low episode count (5-20) to validate flow.
- Once stable, increase episodes and move to larger models.

## What Is Automated vs Manual

### Done in code (already automated)
- Dataset upload/search routes and UI tab.
- Uploaded logs are used during `search_logs` when Splunk is unavailable.
- Multi-agent and campaign environment metrics.
- Training presets API:
  - `GET /api/train/presets`
- Runtime health check:
  - `GET /healthz`

### You still need to do
- In Hugging Face Space, run **Factory Reboot** after dependency changes.
- Set secrets if needed:
  - `HF_TOKEN` (for private model access / push_to_hub)
  - `HF_REPO_ID` (if `push_to_hub=true`)
- Upload your own log files in the **Datasets** tab before training if not using Splunk.
