import os
import operator
from typing import Annotated, List, TypedDict, Optional, Literal

# Load Environment Variables
from dotenv import load_dotenv
load_dotenv()

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage
from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field

# Check if key is loaded
if not os.getenv("OPENAI_API_KEY"):
    raise ValueError("OPENAI_API_KEY not found. Please check your .env file.")

# --- 1. CONFIGURATION & LLM SETUP ---
llm = ChatOpenAI(model="gpt-4o", temperature=0)

# --- 2. COMPLEX DATA STRUCTURES ---

class AttackStep(BaseModel):
    """A single step in the attack plan."""
    step_id: int = Field(description="Step number (1, 2, 3...)")
    name: str = Field(description="Short name of the attack (e.g., 'SSH Brute Force')")
    command: str = Field(description="The exact CLI command or payload (e.g., 'hydra -l root -P pass.txt ssh://10.0.0.5')")
    target: str = Field(description="The target IP or Node Name")
    description: str = Field(description="Reasoning for this step")

class AttackPlan(BaseModel):
    """The full plan containing multiple steps."""
    attack_steps: List[AttackStep]

class StepSimulation(BaseModel):
    """The result of simulating a SINGLE step."""
    step_id: int
    outcome: Literal["BLOCKED", "SUCCESS", "DETECTED"]
    logs: str = Field(description="Detailed narrative of the simulation (e.g., 'Packet reached router, matched ACL 101, dropped.')")

class SimulationResult(BaseModel):
    """The result of the FULL simulation."""
    status: Literal["APPROVED", "REJECTED"]
    step_results: List[StepSimulation]
    failure_reason: Optional[str] = Field(description="If rejected, summarize why.")
    debrief_content: Optional[str] = Field(description="If approved, the final report.")

# --- 3. STATE DEFINITION ---
class RedTeamState(TypedDict):
    cti_report: str
    attack_goal: str
    topology: dict
    # Note: We now store the list of AttackStep objects, not just strings
    plan: List[AttackStep] 
    feedback: str
    final_report: str
    is_approved: bool

# --- 4. AGENT NODES ---

def planner_node(state: RedTeamState):
    print("\n" + "="*50)
    print("🔵 [PLANNER AGENT] ACTIVATED")
    print("="*50)
    
    feedback_context = ""
    if state.get("feedback"):
        print(f"⚠️  FEEDBACK RECEIVED: {state['feedback']}")
        feedback_context = f"\nPREVIOUS PLAN FAILED. FEEDBACK: {state['feedback']}\nYou must adjust the commands/targets to bypass this block."

    system_msg = f"""
    You are an expert Red Team Planner.
    
    GOAL: {state['attack_goal']}
    CTI CONTEXT: {state['cti_report']}
    TOPOLOGY: {state['topology']}
    
    {feedback_context}
    
    Task: Generate a concrete attack plan.
    IMPORTANT: You must output EXACT CLI COMMANDS (payloads) for standard Linux/Network tools (nmap, hydra, ssh, cat, etc).
    """

    planner_llm = llm.with_structured_output(AttackPlan)
    response = planner_llm.invoke([SystemMessage(content=system_msg)])
    
    # --- VERBOSE PRINTING OF THE PLAN ---
    print(f"\n📝 GENERATED PLAN ({len(response.attack_steps)} Steps):")
    for step in response.attack_steps:
        print(f"   [Step {step.step_id}] {step.name}")
        print(f"     ├── 🎯 Target:  {step.target}")
        print(f"     ├── 💻 Command: \033[92m{step.command}\033[0m") # Green color for code
        print(f"     └── ℹ️  Logic:   {step.description}")
        print("-" * 40)
    
    return {"plan": response.attack_steps}


def evaluator_node(state: RedTeamState):
    print("\n" + "="*50)
    print("🟠 [EVALUATOR AGENT] ACTIVATED")
    print("="*50)
    
    # Convert object list to text for the prompt
    plan_text = ""
    for step in state['plan']:
        plan_text += f"Step {step.step_id}: {step.command} (Target: {step.target})\n"
    
    system_msg = f"""
    You are the Network Simulation Engine.
    
    TOPOLOGY CONFIGURATION:
    {state['topology']}
    
    PROPOSED PLAN COMMANDS:
    {plan_text}
    
    Task: Simulate each command line-by-line against the network config.
    
    RULES:
    1. Check Route: Can Source reach Target?
    2. Check ACL/Firewall: Is the specific PORT allowed?
    3. Check Host: Is the service running?
    
    Output a result for EACH step.
    If ANY step is 'BLOCKED', the whole plan is REJECTED.
    """

    evaluator_llm = llm.with_structured_output(SimulationResult)
    result = evaluator_llm.invoke([SystemMessage(content=system_msg)])
    
    # --- VERBOSE PRINTING OF SIMULATION ---
    print("\n🕵️  SIMULATION RESULTS:")
    for res in result.step_results:
        status_icon = "✅" if res.outcome == "SUCCESS" else "❌"
        if res.outcome == "DETECTED": status_icon = "⚠️"
        
        print(f"   [Step {res.step_id}] {status_icon} {res.outcome}")
        print(f"     └── 📜 Log: {res.logs}")

    if result.status == "REJECTED":
        print(f"\n🚫 PLAN REJECTED: {result.failure_reason}")
        return {
            "is_approved": False,
            "feedback": result.failure_reason
        }
    else:
        print("\n✅ PLAN APPROVED. Generating Final Report...")
        return {
            "is_approved": True,
            "final_report": result.debrief_content
        }

# --- 5. EDGE LOGIC ---

def should_continue(state: RedTeamState):
    if state["is_approved"]:
        return "end"
    return "revise"

# --- 6. GRAPH CONSTRUCTION ---

workflow = StateGraph(RedTeamState)
workflow.add_node("planner", planner_node)
workflow.add_node("evaluator", evaluator_node)

workflow.set_entry_point("planner")
workflow.add_edge("planner", "evaluator")
workflow.add_conditional_edges(
    "evaluator",
    should_continue,
    {
        "end": END,
        "revise": "planner"
    }
)

app = workflow.compile()

# --- 7. EXECUTION ---

if __name__ == "__main__":
    
    mock_inputs = {
        "cti_report": "Adversary TTPs: Uses Nmap for discovery, Hydra for SSH brute force, and SCP for exfiltration.",
        "attack_goal": "Dump the 'users' table from the Database Server.",
        "topology": {
            "nodes": [
                {"name": "Attacker-PC", "ip": "192.168.1.100", "role": "attacker"},
                {"name": "Gateway-Router", "ip": "192.168.1.1", "acls": ["permit tcp any host 10.0.0.5 eq 22", "deny tcp any host 10.0.0.5 eq 3306"]}, 
                # ^ ACL Analysis: Allows SSH (22), BLOCKS MySQL (3306) direct access!
                {"name": "DB-Server", "ip": "10.0.0.5", "services": ["ssh", "mysql"], "os": "Ubuntu"}
            ],
            "routes": "Attacker-PC -> Gateway-Router -> DB-Server"
        },
        "plan": [],
        "feedback": "",
        "is_approved": False,
        "final_report": ""
    }

    print("--- STARTING RED TEAM OPERATION ---")
    try:
        final_state = app.invoke(mock_inputs, config={"recursion_limit": 15})
        print("\n\n" + "="*50)
        print("📄 FINAL DEBRIEF REPORT")
        print("="*50)
        print(final_state['final_report'])
    except Exception as e:
        print(f"Error: {e}")