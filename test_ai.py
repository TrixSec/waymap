#!/usr/bin/env python3
"""Test script for AI/LLM integration"""

from lib.ai.llm_provider import get_llm_config, get_llm_provider, is_llm_available
from lib.ai.result_analyzer import analyze_vulnerability


def main():
    print("Testing Waymap AI Integration...")
    print()

    llm_config = get_llm_config()
    print("LLM Configuration:")
    print(f"  Provider: {llm_config.provider}")
    print(f"  Model: {llm_config.model}")
    print(f"  Available: {bool(is_llm_available())}")
    print()

    if is_llm_available():
        print("Testing result analyzer...")
        analysis = analyze_vulnerability(
            vuln_type="XSS",
            url="https://example.com/search?q=test",
            parameter="q",
            payload='<script>alert(1)</script>',
            response_snippet='<script>alert(1)</script> found in response body'
        )
        if analysis:
            print("Analysis result:")
            print(analysis)
        else:
            print("Analysis failed or returned None")
    else:
        print("LLM not configured. Set provider in secrets.json or environment variables.")


if __name__ == "__main__":
    main()
