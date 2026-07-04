from typing import Dict, Any, Optional, List
from lib.ai.llm_provider import get_llm_provider, is_llm_available
from lib.core.logger import get_logger
from lib.ui import print_status

logger = get_logger(__name__)


def generate_payloads(
    vuln_type: str,
    url: str,
    parameter: str,
    context: Optional[str] = None,
    waf_response: Optional[str] = None,
    num_payloads: int = 5
) -> Optional[List[str]]:
    """Generate adaptive payloads for a given vulnerability type using AI.

    Args:
        vuln_type: Type of vulnerability (e.g., 'sqli', 'xss', 'cmdi')
        url: Target URL
        parameter: Vulnerable parameter name
        context: Context from initial tests (e.g., response snippets)
        waf_response: WAF behavior information (if blocked)
        num_payloads: Number of payloads to generate

    Returns:
        List of generated payloads, or None if failed/LLM not available
    """
    if not is_llm_available():
        logger.debug("LLM not available, skipping payload generation")
        return None

    print_status(f"🤖 Generating {vuln_type} payloads for parameter {parameter}", "info")
    logger.info(f"Generating payloads: type={vuln_type}, url={url}, parameter={parameter}")

    system_prompt = """You are a cybersecurity payload generation expert. Your task is to generate valid,
testable payloads for a web vulnerability scanner.

Rules:
- Only generate payloads relevant to the vulnerability type
- Focus on bypass techniques if WAF info is provided
- Keep payloads concise and testable
- Return only JSON with the exact schema provided
- Do not include any explanatory text outside the JSON
- Do not hallucinate or invent arbitrary payloads; use standard techniques

Output schema:
{
    "payloads": ["list", "of", "payloads"]
}"""

    prompt = f"""Generate {num_payloads} test payloads for a {vuln_type} vulnerability.

Target: {url}
Parameter: {parameter}
Context from initial tests: {context or "Not provided"}
WAF behavior/block response: {waf_response or "Not provided"}"""

    json_schema = {
        "type": "object",
        "properties": {
            "payloads": {
                "type": "array",
                "items": {"type": "string"}
            }
        },
        "required": ["payloads"],
        "additionalProperties": False
    }

    try:
        provider = get_llm_provider()
        result = provider.generate(prompt, system_prompt, json_schema)
        payloads = result.get("payloads", [])
        print_status(f"  ✅ Generated {len(payloads)} payloads!", "success")
        logger.info(f"Successfully generated {len(payloads)} payloads")
        return payloads
    except Exception as e:
        print_status(f"  ❌ Failed to generate payloads: {str(e)}", "error")
        logger.error(f"Failed to generate payloads: {e}")
        return None
