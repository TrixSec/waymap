# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Layer 2: AI Agent for analyzing and prioritizing discovery results."""

from typing import List, Dict, Optional, Set
from lib.ai.llm_provider import get_llm_provider, is_llm_available
from lib.discovery.models import DiscoveryResults, DiscoveredURL, DiscoveredForm, DiscoveredAPIEndpoint
from lib.core.logger import get_logger
from lib.ui import print_status

logger = get_logger(__name__)


class DiscoveryAgent:
    """AI agent for analyzing and prioritizing discovery results."""
    
    def __init__(self, discovery_results: DiscoveryResults):
        self.results = discovery_results
        self.prioritized_urls: List[Dict] = []
        self.vulnerability_hints: Dict[str, List[str]] = {}
        self.duplicate_groups: List[List[str]] = []
    
    def analyze_endpoints(self) -> Dict:
        """Analyze discovered endpoints and provide insights."""
        if not is_llm_available():
            return self._basic_analysis()
        
        # Run AI analysis silently without spamming
        
        # Prepare summary data for AI
        summary = self.results.get_summary()
        parameterized_urls = self.results.get_parameterized_urls()
        forms = self.results.get_forms()
        api_endpoints = self.results.get_api_endpoints()
        
        # Sample data for AI analysis (limit to avoid token bloat)
        sample_urls = parameterized_urls[:50]
        sample_forms = forms[:20]
        sample_apis = api_endpoints[:30]
        
        system_prompt = """You are a web security expert analyzing discovered endpoints from a vulnerability scanner.
Your task is to:
1. Identify which endpoints are most likely to be vulnerable
2. Detect duplicate URL patterns (e.g., /product?id=1 and /product?id=2)
3. Suggest which endpoints should be prioritized for scanning
4. Identify potential admin panels or high-value targets

Return a JSON object with the following structure:
{
    "vulnerability_likelihood": [
        {"url": "endpoint", "reason": "explanation", "risk_level": "high|medium|low"}
    ],
    "duplicate_patterns": [
        {"pattern": "/product?id=*", "examples": ["/product?id=1", "/product?id=2"]}
    ],
    "priority_order": ["url1", "url2", ...],
    "high_value_targets": ["url1", "url2", ...],
    "admin_panels": ["url1", "url2", ...],
    "recommendations": ["tip1", "tip2", ...]
}"""
        
        prompt = f"""Analyze these discovered endpoints from {self.results.base_url}:

Summary:
- Total URLs: {summary['total_urls']}
- Parameterized URLs: {summary['parameterized_urls']}
- Forms: {summary['forms']}
- API Endpoints: {summary['api_endpoints']}
- JS Endpoints: {summary['js_endpoints']}

Sample Parameterized URLs:
{self._format_urls(sample_urls)}

Sample Forms:
{self._format_forms(sample_forms)}

Sample API Endpoints:
{self._format_apis(sample_apis)}

Provide your analysis."""
        
        json_schema = {
            "type": "object",
            "properties": {
                "vulnerability_likelihood": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "reason": {"type": "string"},
                            "risk_level": {"type": "string", "enum": ["high", "medium", "low"]}
                        },
                        "required": ["url", "reason", "risk_level"]
                    }
                },
                "duplicate_patterns": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "pattern": {"type": "string"},
                            "examples": {"type": "array", "items": {"type": "string"}}
                        },
                        "required": ["pattern", "examples"]
                    }
                },
                "priority_order": {"type": "array", "items": {"type": "string"}},
                "high_value_targets": {"type": "array", "items": {"type": "string"}},
                "admin_panels": {"type": "array", "items": {"type": "string"}},
                "recommendations": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["vulnerability_likelihood", "duplicate_patterns", "priority_order", "high_value_targets", "admin_panels", "recommendations"]
        }
        
        try:
            provider = get_llm_provider()
            analysis = provider.generate(prompt, system_prompt, json_schema)
            
            self.prioritized_urls = analysis.get("vulnerability_likelihood", [])
            self.duplicate_groups = analysis.get("duplicate_patterns", [])
            
            # Only print if we actually found something
            if self.prioritized_urls:
                print_status(f"AI identified {len(self.prioritized_urls)} high-priority endpoints", "success")
            
            return analysis
            
        except Exception as e:
            # Silently fall back to basic analysis without spamming
            return self._basic_analysis()
    
    def _format_urls(self, urls: List[DiscoveredURL]) -> str:
        """Format URLs for AI prompt."""
        return "\n".join([f"- {u.url} (params: {', '.join(u.params)})" for u in urls])
    
    def _format_forms(self, forms: List[DiscoveredForm]) -> str:
        """Format forms for AI prompt."""
        return "\n".join([f"- {f.action} ({f.method.value}) inputs: {list(f.inputs.keys())}" for f in forms])
    
    def _format_apis(self, apis: List[DiscoveredAPIEndpoint]) -> str:
        """Format API endpoints for AI prompt."""
        return "\n".join([f"- {a.endpoint} ({a.source})" for a in apis])
    
    def _basic_analysis(self) -> Dict:
        """Perform basic heuristic analysis without AI."""
        logger.info("Performing basic heuristic analysis")
        
        vulnerability_likelihood = []
        duplicate_patterns = []
        priority_order = []
        high_value_targets = []
        admin_panels = []
        recommendations = []
        
        # Heuristic: URLs with many parameters are higher risk
        param_urls = self.results.get_parameterized_urls()
        param_urls.sort(key=lambda x: len(x.params), reverse=True)
        
        for url_obj in param_urls[:20]:
            risk = "high" if len(url_obj.params) >= 3 else "medium" if len(url_obj.params) >= 2 else "low"
            vulnerability_likelihood.append({
                "url": url_obj.url,
                "reason": f"Has {len(url_obj.params)} parameters",
                "risk_level": risk
            })
        
        # Heuristic: Admin panels
        admin_keywords = ['admin', 'dashboard', 'panel', 'console', 'manage', 'administrator']
        for url_obj in self.results.urls:
            if any(keyword in url_obj.url.lower() for keyword in admin_keywords):
                admin_panels.append(url_obj.url)
                high_value_targets.append(url_obj.url)
        
        # Heuristic: API endpoints
        for api in self.results.api_endpoints:
            if 'api' in api.endpoint.lower():
                high_value_targets.append(api.endpoint)
        
        # Heuristic: Forms with POST method
        for form in self.results.forms:
            if form.method.value == 'POST':
                high_value_targets.append(form.action)
        
        # Basic priority order
        priority_order = high_value_targets[:20]
        
        # Recommendations
        recommendations = [
            "Prioritize endpoints with multiple parameters",
            "Check admin panels for authentication bypass",
            "Test API endpoints for injection vulnerabilities",
            "Analyze forms with POST method for CSRF/XSS"
        ]
        
        return {
            "vulnerability_likelihood": vulnerability_likelihood,
            "duplicate_patterns": duplicate_patterns,
            "priority_order": priority_order,
            "high_value_targets": high_value_targets,
            "admin_panels": admin_panels,
            "recommendations": recommendations
        }
    
    def get_scan_queue(self, limit: Optional[int] = None) -> List[str]:
        """Get prioritized scan queue based on analysis."""
        if not self.prioritized_urls:
            # If no AI analysis, use basic prioritization
            analysis = self.analyze_endpoints()
            priority_order = analysis.get("priority_order", [])
        else:
            priority_order = [item["url"] for item in self.prioritized_urls]
        
        if limit:
            return priority_order[:limit]
        return priority_order
    
    def get_vulnerability_hints(self) -> Dict[str, List[str]]:
        """Get vulnerability hints for specific endpoints."""
        hints = {}
        
        for item in self.prioritized_urls:
            url = item["url"]
            reason = item["reason"]
            risk = item["risk_level"]
            
            hints[url] = [
                f"Risk Level: {risk}",
                f"Reason: {reason}"
            ]
            
            # Add specific hints based on risk level
            if risk == "high":
                hints[url].append("Recommend: Test for SQL injection, XSS, and command injection")
            elif risk == "medium":
                hints[url].append("Recommend: Test for XSS and open redirect")
        
        return hints
    
    def deduplicate_urls(self) -> List[str]:
        """Remove duplicate URLs based on pattern analysis."""
        unique_urls = set()
        
        # If AI analysis found duplicate patterns, use them
        if self.duplicate_groups:
            for pattern_group in self.duplicate_groups:
                pattern = pattern_group.get("pattern", "")
                examples = pattern_group.get("examples", [])
                if examples:
                    # Keep only the first example as representative
                    unique_urls.add(examples[0])
        
        # Add all other URLs
        all_urls = self.results.get_all_unique_urls()
        for url in all_urls:
            # Check if URL matches any duplicate pattern
            is_duplicate = False
            for pattern_group in self.duplicate_groups:
                pattern = pattern_group.get("pattern", "")
                if pattern and "*" in pattern:
                    # Simple pattern matching
                    pattern_prefix = pattern.replace("*", "")
                    if url.startswith(pattern_prefix):
                        is_duplicate = True
                        break
            
            if not is_duplicate:
                unique_urls.add(url)
        
        return list(unique_urls)
