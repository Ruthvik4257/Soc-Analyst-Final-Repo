---
title: SOC Analyst Env
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: docker
pinned: false
---

# SOC Analyst Incident Triage Environment

A real-world OpenEnv environment where an AI agent acts as a Tier 1 Security Operations Center (SOC) analyst. The agent must triage incoming security alerts by gathering evidence from simulated logs, threat intelligence, and asset databases before making a final resolution.

## Task Details
The environment provides 3 tasks (easy, medium, hard) simulating real-world alerts:
1. **Easy**: Brute force login attempt.
2. **Medium**: Critical malware infection.
3. **Hard**: Impossible travel alert (VPN exit node false positive).

## Actions
The agent can query internal tools using the following actions:
- `search_logs`: Query firewall/authentication logs.
- `get_threat_intel`: Look up the reputation of an IP or file hash.
- `get_asset_info`: Get the owner and criticality of a hostname or user.
- `take_action`: Make the final decision (`false_positive`, `escalate_tier2`, `block_if_malicious`).

## Grading & Rewards
- **Rewards**: The environment yields partial rewards (+0.1 to +0.3) when the agent correctly gathers necessary contextual evidence for the specific alert.
- **Grader Score**: The final action is evaluated against the ground truth. A score of `1.0` is awarded for the correct decision, `0.0` for an incorrect one, and `0.1` if the correct decision was guessed without gathering the necessary evidence (like checking Threat Intel for an IP).

## Files Overview
- `models.py`: Defines the strictly typed `SocAction` and `SocObservation` Pydantic models.
- `server/environment.py`: Contains the environment logic, tasks, and reward shaping.
- `inference.py`: Uses the OpenAI client to run a language model against all 3 tasks and produce a final grader report.

## Usage
1. Provide your LLM credentials:
   ```bash
   export OPENAI_API_KEY="your_api_key_here"  # Or use HF_TOKEN
   export MODEL_NAME="gpt-4o"
   ```
2. Run the baseline inference script:
   ```bash
   python inference.py
   ```

## Hugging Face Space Deployment

This repository is already configured as a Docker Space (`sdk: docker` in the README frontmatter).

### 1) Push this repo to a Hugging Face Space
- Create a new Space on Hugging Face.
- Choose **Docker** SDK.
- Push this project files to that Space repository.

### 2) Configure Space secrets
Set these in **Space Settings -> Variables and secrets**:
- `HF_TOKEN` (required if you want to push trained checkpoints to Hub)
- `HF_REPO_ID` (example: `username/soc-ppo-agent`)
- `HF_MODEL_NAME` (optional, default: `distilgpt2`)
- `TRAIN_LR` (optional, default: `1e-5`)
- `TRAIN_OUTPUT_DIR` (optional, default: `./artifacts/ppo-soc-model`)
- `SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_USERNAME`, `SPLUNK_PASSWORD`, `SPLUNK_SCHEME` (optional, if using live Splunk)

### 3) Training API payload for TRL PPO
Call:
- `POST /api/train`
With JSON:
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
- Once stable, increase episodes and switch to larger models.
