"""
Backward-compatibility shim.

All prompts now live in agents/sheila/config.py.
Existing code that imports build_system_prompt() from this module
continues to work unchanged.
"""

from agents.sheila.config import SHEILA_CONFIG


def build_system_prompt(mode: str = "judge") -> str:
    """
    Build the base system prompt for the Sheila agent.

    Args:
        mode: "judge" | "admin" | "redteam"
    """
    return SHEILA_CONFIG.get_system_prompt(mode)
