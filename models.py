from typing import Dict, List, Optional, Literal
from pydantic import Field
from openenv.core.env_server import Action, Observation, State


AgentRole = Literal["supervisor", "log_hunter", "threat_intel"]
DecisionType = Literal["false_positive", "escalate_tier2", "block_if_malicious"]


class AgentMessage(State):
    sender: AgentRole
    recipient: Literal["supervisor", "log_hunter", "threat_intel", "broadcast"]
    message_type: Literal["delegate", "report", "clarification", "final_decision"]
    payload: str
    confidence: float = 0.5
    evidence_refs: List[str] = Field(default_factory=list)


class AgentObservation(State):
    role: AgentRole
    visible_alert: Dict = Field(default_factory=dict)
    visible_evidence: List[str] = Field(default_factory=list)
    messages_for_agent: List[AgentMessage] = Field(default_factory=list)
    step_hint: str = ""


class EpisodeMetrics(State):
    useful_actions: int = 0
    total_actions: int = 0
    negotiation_rounds: int = 0
    contradictions_resolved: int = 0
    invalid_actions: int = 0
    tool_failures: int = 0
    evidence_sufficiency: float = 0.0
    coordination_efficiency: float = 0.0
    campaign_stage: str = "n/a"
    campaign_progress: float = 0.0
    delayed_reward_buffer: float = 0.0
    recovery_after_mistake: float = 0.0
    memory_consistency_score: float = 0.0
    mistakes_made: int = 0
    recovery_actions: int = 0
    per_agent_rewards: Dict[AgentRole, float] = Field(
        default_factory=lambda: {"supervisor": 0.0, "log_hunter": 0.0, "threat_intel": 0.0}
    )


class SocAction(Action):
    action_type: Literal[
        "search_logs",
        "get_threat_intel",
        "get_asset_info",
        "take_action",
        "delegate_log_hunter",
        "delegate_threat_intel",
        "submit_log_report",
        "submit_ti_report",
        "request_clarification",
    ]
    query: Optional[str] = None
    time_range: Optional[str] = None
    indicator: Optional[str] = None
    hostname_or_user: Optional[str] = None
    decision: Optional[DecisionType] = None
    reason: Optional[str] = None
    agent_role: Optional[AgentRole] = None
    confidence: Optional[float] = None
    report: Optional[str] = None

class SocObservation(Observation):
    message: str
    remaining_steps: int
    alert_details: dict
    evidence_collected: List[str]
    score: Optional[float] = None
    mode: Literal["single_agent", "multi_agent", "campaign"] = "single_agent"
    active_agent: Optional[AgentRole] = None
    transcript: List[AgentMessage] = Field(default_factory=list)
    agent_observations: List[AgentObservation] = Field(default_factory=list)
    episode_metrics: Optional[EpisodeMetrics] = None

class SocState(State):
    difficulty: str = "easy"
    mode: Literal["single_agent", "multi_agent", "campaign"] = "single_agent"
    alert: dict = Field(default_factory=dict)
    remaining_steps: int = 10
    evidence_collected: List[str] = Field(default_factory=list)
    transcript: List[AgentMessage] = Field(default_factory=list)
    active_agent: AgentRole = "supervisor"
    turn_index: int = 0
    per_agent_memory: Dict[AgentRole, List[str]] = Field(
        default_factory=lambda: {"supervisor": [], "log_hunter": [], "threat_intel": []}
    )
    campaign_stages: List[str] = Field(default_factory=list)
    campaign_stage_index: int = 0
    delayed_reward_bank: float = 0.0
    mistake_made: bool = False
    recovered_after_mistake: bool = False
    episode_metrics: EpisodeMetrics = Field(default_factory=EpisodeMetrics)
    # Ground truth answers for grading
    expected_decision: str = ""
    # Whether episode ended successfully
    score: float = 0.01
