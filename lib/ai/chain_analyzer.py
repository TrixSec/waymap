from typing import Dict, Any, Optional, List
from lib.ai.llm_provider import get_llm_provider, is_llm_available
from lib.core.logger import get_logger
from lib.ui import print_status

logger = get_logger(__name__)


def analyze_finding_chains(
    findings: List[Dict[str, Any]],
    target: str
) -> Optional[List[Dict[str, Any]]]:
    """
    Analyze findings to identify potential vulnerability chains using AI.
    
    Args:
        findings: List of vulnerability findings
        target: Target URL
        
    Returns:
        List of potential chains or None
    """
    if not is_llm_available() or len(findings) < 2:
        logger.debug("LLM not available or too few findings, skipping chain analysis")
        return None
    
    print_status("Analyzing findings for potential chains...", "info")
    logger.info("Analyzing finding chains using AI")
    
    system_prompt = """You are a cybersecurity exploit chain analyst. Your task is to identify potential 
vulnerability chains from the provided findings.

Rules:
- Focus on realistic, actionable chains
- Be specific about the attack flow
- Return JSON array of chains with:
  [
    {
      "chain_name": "string",
      "chain_description": "string",
      "severity": "high/medium/low",
      "finding_indices": [0, 2],
      "attack_flow": ["step1", "step2"],
      "confidence": 0-1
    }
  ]"""
    
    # Format findings for prompt
    finding_descriptions = []
    for i, f in enumerate(findings):
        finding_descriptions.append(f"Finding {i}: {f.get('type', 'unknown')} at {f.get('url', 'unknown')} (param: {f.get('parameter', 'unknown')})")
    
    prompt = f"Analyze these findings for potential chains:\n\n" + "\n".join(finding_descriptions)
    
    json_schema = {
        "type": "object",
        "properties": {
            "chains": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "chain_name": {"type": "string"},
                        "chain_description": {"type": "string"},
                        "severity": {"type": "string"},
                        "finding_indices": {"type": "array", "items": {"type": "integer"}},
                        "attack_flow": {"type": "array", "items": {"type": "string"}},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1}
                    },
                    "required": ["chain_name", "chain_description", "severity", "finding_indices", "attack_flow", "confidence"]
                }
            }
        },
        "required": ["chains"],
        "additionalProperties": False
    }
    
    try:
        provider = get_llm_provider()
        result = provider.generate(prompt, system_prompt, json_schema)
        chains = result.get("chains", [])
        print_status(f"Identified {len(chains)} potential chains!", "success")
        return chains
        
    except Exception as e:
        print_status(f"Failed to analyze chains: {str(e)}", "error")
        logger.error(f"Failed to analyze chains: {e}")
        return None
