import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from openenv.core.env_client import EnvClient
from openenv.core.client_types import StepResult
from models import SocAction, SocObservation, SocState

class SocAnalystEnv(EnvClient[SocAction, SocObservation, SocState]):
    def _step_payload(self, action: SocAction) -> dict:
        return action.dict(exclude_none=True)

    def _parse_result(self, payload: dict) -> StepResult:
        obs_data = payload.get("observation", {})
        return StepResult(
            observation=SocObservation(
                done=payload.get("done", False),
                reward=payload.get("reward"),
                message=obs_data.get("message", ""),
                remaining_steps=obs_data.get("remaining_steps", 0),
                alert_details=obs_data.get("alert_details", {}),
                evidence_collected=obs_data.get("evidence_collected", []),
                score=obs_data.get("score", 0.0),
            ),
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: dict) -> SocState:
        return SocState(
            episode_id=payload.get("episode_id", ""),
            step_count=payload.get("step_count", 0),
            difficulty=payload.get("difficulty", "easy"),
            alert=payload.get("alert", {}),
            remaining_steps=payload.get("remaining_steps", 10),
            evidence_collected=payload.get("evidence_collected", []),
            expected_decision=payload.get("expected_decision", ""),
            score=payload.get("score", 0.0)
        )
