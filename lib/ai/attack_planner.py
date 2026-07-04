from typing import Dict, Any, Optional, List
from lib.ai.llm_provider import get_llm_provider, is_llm_available
from lib.core.logger import get_logger
from lib.ui import print_status

logger = get_logger(__name__)


def plan_attack_steps(
    vuln_type: str,
    url: str,
    parameter: str,
    test_results: Optional[List[Dict[str, Any]]] = None,
    previous_responses: Optional[List[str]] = None
) -> Optional[Dict[str, Any]]:
    """Plan next attack steps based on previous test results using AI.

    Args:
        vuln_type: Type of vulnerability
        url: Target URL
        parameter: Parameter being tested
        test_results: Results from previous tests
        previous_responses: List of response snippets from previous tests

    Returns:
        Dict with attack plan, or None
    """
    if not is_llm_available():
        logger.debug("LLM not available, skipping attack planning")
        return None

    print_status(f"🤖 Planning next attack steps for {vuln_type} on {url}", "info")
    logger.info(f"Planning attack steps: type={vuln_type}, url={url}, parameter={parameter}")

    system_prompt = """You are a cybersecurity attack planning expert. Your task is to analyze test results
and plan the next steps for vulnerability testing.

Rules:
- Only base your plan on the provided test results
- Be specific about what tests to run next
- Return only JSON with the exact schema provided
- Do not include explanatory text outside the JSON

Output schema:
{
    "next_tests": ["list", "of", "next", "test", "descriptions"],
    "payload_suggestions": ["list", "of", "payloads", "to", "try"],
    "confidence": 0-1 (how confident you are in the plan),
    "reasoning": "why you suggest these steps"
}"""

    prompt = f"""Plan next attack steps for {vuln_type} vulnerability:

Target URL: {url}
Parameter: {parameter}
Previous test results: {str(test_results) if test_results else "None"}
Previous responses: {str(previous_responses)[:5000] if previous_responses else "None"}"""

    json_schema = {
        "type": "object",
        "properties": {
            "next_tests": {"type": "array", "items": {"type": "string"}},
            "payload_suggestions": {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "reasoning": {"type": "string"}
        },
        "required": ["next_tests", "payload_suggestions", "confidence", "reasoning"],
        "additionalProperties": False
    }

    try:
        provider = get_llm_provider()
        result = provider.generate(prompt, system_prompt, json_schema)
        print_status("  ✅ Attack plan generated!", "success")
        logger.info("Successfully generated attack plan")
        return result
    except Exception as e:
        print_status(f"  ❌ Failed to generate attack plan: {str(e)}", "error")
        logger.error(f"Failed to generate attack plan: {e}")
        return None
