from typing import Dict, Any, Optional, List
from lib.ai.llm_provider import get_llm_provider, is_llm_available
from lib.core.logger import get_logger
from lib.ui import print_status

logger = get_logger(__name__)


def generate_executive_summary(
    findings: List[Dict[str, Any]],
    target: str
) -> Optional[str]:
    """
    Generate an executive summary of the findings using AI.
    
    Args:
        findings: List of vulnerability findings
        target: Target URL
        
    Returns:
        Executive summary text or None if failed
    """
    if not is_llm_available() or not findings:
        logger.debug("LLM not available or no findings, skipping executive summary")
        return None
    
    print_status("Generating AI executive summary...", "info")
    logger.info("Generating AI executive summary")
    
    system_prompt = """You are a cybersecurity report writer. Your task is to generate a concise, 
professional executive summary of security findings.

Rules:
- Keep it under 300 words
- Focus on severity and impact
- Avoid technical jargon
- Structure it as a single paragraph"""
    
    prompt = f"Generate an executive summary for security findings on: {target}\n\nFindings (severity): {', '.join([f.get('type', 'unknown') + ' (' + str(f.get('severity', 'unknown')) + ')' for f in findings])}"
    
    try:
        provider = get_llm_provider()
        result = provider.generate(prompt, system_prompt)
        
        if isinstance(result, dict):
            summary = result.get('summary', '') or result.get('content', '') or str(result)
        else:
            summary = str(result)
            
        print_status("Executive summary generated!", "success")
        return summary.strip()
        
    except Exception as e:
        print_status(f"Failed to generate executive summary: {str(e)}", "error")
        logger.error(f"Failed to generate executive summary: {e}")
        return None


def enhance_report_data(
    results: Dict[str, Any],
    target: str
) -> Dict[str, Any]:
    """
    Enhance report data with AI-generated content.
    
    Args:
        results: Scan results dictionary
        target: Target URL
        
    Returns:
        Enhanced results dictionary
    """
    if not is_llm_available():
        return results
    
    enhanced = results.copy()
    all_findings = []
    
    for scan_entry in enhanced.get('scans', []):
        for scan_type, findings in scan_entry.items():
            if isinstance(findings, list):
                all_findings.extend(findings)
            elif isinstance(findings, dict):
                for sub_findings in findings.values():
                    if isinstance(sub_findings, list):
                        all_findings.extend(sub_findings)
    
    if all_findings:
        summary = generate_executive_summary(all_findings, target)
        if summary:
            enhanced['ai_enhanced'] = True
            enhanced['executive_summary'] = summary
    
    return enhanced
