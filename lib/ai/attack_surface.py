from typing import Dict, Any, Optional, List
from lib.ai.llm_provider import get_llm_provider, is_llm_available
from lib.core.logger import get_logger
from lib.ui import print_status

logger = get_logger(__name__)


def discover_attack_surface(
    url: str,
    html_content: Optional[str] = None,
    js_content: Optional[List[str]] = None,
    headers: Optional[Dict[str, str]] = None
) -> Optional[Dict[str, Any]]:
    """Discover potential attack surfaces from a web page using AI.

    Args:
        url: Target URL
        html_content: HTML content of the page
        js_content: List of JavaScript content/URLs
        headers: Response headers

    Returns:
        Dict with discovered attack surface info, or None
    """
    if not is_llm_available():
        logger.debug("LLM not available, skipping attack surface discovery")
        return None

    print_status(f"🤖 Analyzing attack surface for {url}", "info")
    logger.info(f"Analyzing attack surface: url={url}")

    system_prompt = """You are a cybersecurity attack surface analyst. Your task is to analyze a web page
and identify potential attack surfaces.

Rules:
- Only identify attack surfaces present in the provided content
- Be specific and factual; do not invent or hallucinate
- Return only JSON with the exact schema provided
- Do not include explanatory text outside the JSON

Output schema:
{
    "endpoints": ["list", "of", "potential", "endpoints"],
    "parameters": ["list", "of", "potential", "parameters"],
    "hidden_forms": ["list", "of", "hidden", "form", "details"],
    "api_calls": ["list", "of", "api", "call", "details"],
    "notes": "additional notes about the attack surface"
}"""

    prompt = f"""Analyze the attack surface of this URL: {url}

HTML Content (snippet): {html_content[:5000] if html_content else "Not provided"}
JavaScript Content: {str(js_content)[:5000] if js_content else "Not provided"}
Response Headers: {str(headers) if headers else "Not provided"}"""

    json_schema = {
        "type": "object",
        "properties": {
            "endpoints": {"type": "array", "items": {"type": "string"}},
            "parameters": {"type": "array", "items": {"type": "string"}},
            "hidden_forms": {"type": "array", "items": {"type": "string"}},
            "api_calls": {"type": "array", "items": {"type": "string"}},
            "notes": {"type": "string"}
        },
        "required": ["endpoints", "parameters", "hidden_forms", "api_calls", "notes"],
        "additionalProperties": False
    }

    try:
        provider = get_llm_provider()
        result = provider.generate(prompt, system_prompt, json_schema)
        print_status("  ✅ Attack surface analysis complete!", "success")
        logger.info("Successfully analyzed attack surface")
        return result
    except Exception as e:
        print_status(f"  ❌ Failed to analyze attack surface: {str(e)}", "error")
        logger.error(f"Failed to analyze attack surface: {e}")
        return None
