from typing import Dict, Any, Optional
from lib.ai.llm_provider import get_llm_provider, is_llm_available
from lib.core.logger import get_logger
from lib.ui import print_status

logger = get_logger(__name__)


def analyze_vulnerability(
    vuln_type: str,
    url: str,
    parameter: str,
    payload: str,
    response_snippet: Optional[str] = None,
    details: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Analyze a vulnerability using AI and return structured analysis."""
    if not is_llm_available():
        logger.debug("LLM not available, skipping vulnerability analysis")
        return None

    print_status(f"Analyzing {vuln_type} vulnerability at {url}", "info")
    logger.info(f"Analyzing vulnerability: type={vuln_type}, url={url}, parameter={parameter}")

    system_prompt = """You are a cybersecurity vulnerability analyst. Your task is to analyze a detected vulnerability and provide structured analysis.

Rules:
- Be factual and only reference the provided information
- Do not invent or hallucinate details
- Use JSON format with the exact schema provided
- Keep responses concise and professional

Output schema:
{
    "severity_justification": "string - explain why this severity is appropriate",
    "impact": "string - explain the potential impact of this vulnerability",
    "remediation_steps": ["list", "of", "steps"],
    "false_positive_likelihood": 0-1 (0 = no, 1 = definitely),
    "confidence_score": 0-1 (0 = low, 1 = high)
}"""

    prompt = f"""Analyze this vulnerability:
- Type: {vuln_type}
- URL: {url}
- Parameter: {parameter}
- Payload: {payload}
- Response snippet: {response_snippet or "Not provided"}
- Details: {details or "Not provided"}"""

    json_schema = {
        "type": "object",
        "properties": {
            "severity_justification": {"type": "string"},
            "impact": {"type": "string"},
            "remediation_steps": {"type": "array", "items": {"type": "string"}},
            "false_positive_likelihood": {"type": "number", "minimum": 0, "maximum": 1},
            "confidence_score": {"type": "number", "minimum": 0, "maximum": 1}
        },
        "required": ["severity_justification", "impact", "remediation_steps", "false_positive_likelihood", "confidence_score"],
        "additionalProperties": False
    }

    try:
        provider = get_llm_provider()
        analysis = provider.generate(prompt, system_prompt, json_schema)
        logger.info("Successfully analyzed vulnerability")
        return analysis
    except Exception as e:
        print_status(f"Failed to analyze vulnerability: {str(e)}", "error")
        logger.error(f"Failed to analyze vulnerability: {e}")
        return None
