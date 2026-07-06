from typing import Dict, Any, Optional
from functools import lru_cache
from lib.ai.llm_provider import get_llm_provider, is_llm_available
from lib.core.logger import get_logger
from lib.ui import print_status

logger = get_logger(__name__)


def check_false_positive(
    vuln_type: str,
    url: str,
    parameter: str,
    payload: str,
    response_content: Optional[str] = None,
    request_method: str = "GET"
) -> Optional[Dict[str, Any]]:
    """
    Check if a vulnerability finding might be a false positive using AI.
    
    Args:
        vuln_type: Type of vulnerability
        url: Target URL
        parameter: Vulnerable parameter
        payload: Payload used
        response_content: Response content snippet
        request_method: HTTP method used
        
    Returns:
        Dictionary with false positive analysis or None
    """
    return _check_false_positive_cached(vuln_type, url, parameter, payload, response_content or "", request_method)


@lru_cache(maxsize=1024)
def _check_false_positive_cached(
    vuln_type: str,
    url: str,
    parameter: str,
    payload: str,
    response_content: str = "",
    request_method: str = "GET"
) -> Optional[Dict[str, Any]]:
    if not is_llm_available():
        logger.debug("LLM not available, skipping false positive check")
        return None
    
    print_status(f"Checking {vuln_type} finding for false positive...", "info")
    logger.info(f"Checking false positive: {vuln_type} at {url}")
    
    system_prompt = """You are a cybersecurity vulnerability validator. Your task is to analyze a 
vulnerability finding and assess the likelihood it is a false positive.

Rules:
- Be conservative - don't mark as false positive without strong evidence
- Focus on response patterns and context
- Return JSON in the exact schema:
  {
    "is_likely_false_positive": boolean,
    "confidence": 0-1,
    "reasoning": "string"
  }"""
    
    prompt = f"""Analyze this vulnerability finding:

Type: {vuln_type}
URL: {url}
Parameter: {parameter}
Payload: {payload}
Method: {request_method}
Response: {response_content[:2000] if response_content else "Not provided"}"""
    
    json_schema = {
        "type": "object",
        "properties": {
            "is_likely_false_positive": {"type": "boolean"},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "reasoning": {"type": "string"}
        },
        "required": ["is_likely_false_positive", "confidence", "reasoning"],
        "additionalProperties": False
    }
    
    try:
        provider = get_llm_provider()
        result = provider.generate(prompt, system_prompt, json_schema)
        print_status("False positive check complete!", "success")
        return result
        
    except Exception as e:
        print_status(f"Failed to check false positive: {str(e)}", "error")
        logger.error(f"Failed to check false positive: {e}")
        return None
