import os
import sys
import json
from openai import OpenAI

from server.environment import SocAnalystEnvironment
from models import SocAction

def run_inference(task_difficulty: str):
    # Initialize LLM client
    api_key = os.environ.get("OPENAI_API_KEY", os.environ.get("HF_TOKEN"))
    api_base = os.environ.get("API_BASE_URL")
    model_name = os.environ.get("MODEL_NAME", "gpt-4o-mini")

    client = OpenAI(
        api_key=api_key,
        base_url=api_base
    )

    env = SocAnalystEnvironment()
    obs = env.reset(difficulty=task_difficulty)
    print(f"\n--- Starting Task: {task_difficulty} ---")
    
    messages = [
        {"role": "system", "content": """You are an AI SOC Analyst.
You must investigate security alerts and make a final decision. You have the following actions available. You MUST return ONLY a JSON object representing the action, and nothing else. Do not use markdown blocks.
Actions:
1. {"action_type": "search_logs", "query": "ip_or_username"}
2. {"action_type": "get_threat_intel", "indicator": "ip_or_hash"}
3. {"action_type": "get_asset_info", "hostname_or_user": "hostname_or_user"}
4. {"action_type": "take_action", "decision": "false_positive" | "escalate_tier2" | "block_if_malicious", "reason": "str"}

Always gather evidence using search_logs, get_threat_intel, and get_asset_info before making a take_action decision!"""}
    ]
    
    done = False
    reward = 0.0
    
    while not done:
        # Provide current observation
        obs_dump = {
            "message": obs.message,
            "remaining_steps": obs.remaining_steps,
            "alert_details": obs.alert_details,
            "evidence_collected": obs.evidence_collected
        }
        messages.append({"role": "user", "content": f"Current Observation:\n{json.dumps(obs_dump)}\n\nWhat is your next action JSON?"})
        
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=messages,
                temperature=0.0
            )
            llm_text = response.choices[0].message.content.strip()
            
            # Remove Markdown block if present
            if llm_text.startswith("```json"):
                llm_text = llm_text[7:-3].strip()
            elif llm_text.startswith("```"):
                llm_text = llm_text[3:-3].strip()
                
            action_dict = json.loads(llm_text)
            action = SocAction(**action_dict)
            print(f"Agent Action: {action.action_type} - {action_dict}")
            
            messages.append({"role": "assistant", "content": llm_text})
            
            obs = env.step(action)
            done = obs.done
            reward = obs.reward
            print(f"Env Reply: {obs.message}")
            
        except Exception as e:
            print(f"Error during LLM call or parsing: {e}")
            break

    score = env.state.score
    print(f"Task {task_difficulty} Finished! Final Reward: {reward}, Score: {score}")
    return score

if __name__ == "__main__":
    if not os.environ.get("OPENAI_API_KEY") and not os.environ.get("HF_TOKEN"):
         print("Warning: Neither OPENAI_API_KEY nor HF_TOKEN is set. API calls may fail.")

    scores = {}
    for diff in ["easy", "medium", "hard"]:
        score = run_inference(diff)
        scores[diff] = score
        
    print("\n=== Final Grader Report ===")
    for task, sc in scores.items():
        print(f"Task: {task:<10} Score: {sc}")
