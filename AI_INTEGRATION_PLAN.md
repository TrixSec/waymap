# Waymap AI/LLM Integration Plan

## Overview
This document outlines a structured approach to integrating generative AI (LLMs) into Waymap to enhance its capabilities without hallucination risks.

---

## Core Principles (From Your Plan)
1. **AI is an Assistant, Not the Scanner**: LLMs don't execute attacks or verify vulnerabilities – they suggest, explain, and reason.
2. **Hallucination Mitigation**: Use LLMs only for tasks that can be verified with concrete data.
3. **Human-in-the-Loop**: All LLM-generated content is reviewable and overrideable.
4. **Modularity**: AI features are optional and configurable.
5. **Transparency**: Clearly mark LLM-generated output.
6. **Security**: Never send sensitive data to third-party LLMs without explicit user consent.

---

## Where AI Provides Real Value (From Your Plan)

### ✅ 1. Adaptive Payload Generation
Instead of fixed payload lists, AI generates payloads based on:
- Framework fingerprints (Laravel, Django, Spring, etc.)
- Error messages
- Reflection context
- WAF behavior

**Example**:
- Static payload: `' OR 1=1--`
- AI-generated: Payload tailored to bypass a specific WAF or template engine

**Key**: All payloads must be verified by the scanner's deterministic engine.

---

### ✅ 2. Smarter Crawling
AI inspects:
- JavaScript
- React/Vue bundles
- API routes
- Hidden forms
- GraphQL schemas

AI suggests:
- `/api/internal/users`
- `/admin/debug`
- Hidden parameters
- Undocumented endpoints

**Key**: The crawler then verifies they exist.

---

### ✅ 3. Attack Surface Discovery
LLMs read HTML/JS and infer:
- Possible parameters
- Upload endpoints
- Authentication flows
- SSRF candidates
- IDOR opportunities

**Key**: These are suggestions – not findings.

---

### ✅ 4. Multi-Step Reasoning
Many scanners work like:
```
payload → response → yes/no
```

AI can reason across multiple observations:
```
Response A → reflected
Response B → encoded
Response C → bypasses filter
```
→ Try SVG payload → Try event handler → Try JSON context

This becomes an iterative attack planner.

---

### ✅ 5. Chaining Findings
Suppose Waymap finds:
- Open redirect
- Exposed API
- Weak CORS
- JWT disclosure

AI suggests: "These may be chainable into account takeover."

**Key**: Normal scanners treat them separately.

---

## ❌ Where AI Should NOT Be Trusted
AI should never be the authority for:
- SQL Injection detection
- XSS confirmation
- RCE confirmation
- SSRF confirmation
- Authentication bypass
- CSRF validation

These require deterministic verification.

**Never output**: "AI thinks this is SQLi"
**Instead output**: "Scanner confirmed SQLi. AI explains impact and remediation."

---

## The AI-Assisted Autonomous Scanner (From Your Plan)
The ideal flow:
1. **Crawler** → Finds endpoints
2. **Endpoint Discovery** → Maps attack surface
3. **AI Suggests New Vectors** → Hypothesizes
4. **Scanner Verifies** → Deterministic checks
5. **AI Analyzes Verified Findings** → Explains
6. **AI Plans Additional Tests** → Next steps
7. **Scanner Executes** → Verifies again

This creates a feedback loop:
```
Scan → Observe → Reason (AI) → Generate Hypotheses → Verify → Repeat
```

---

## Current Implementation Status

### ✅ Completed (Phase 1 MVP)
- **1. LLM Provider Abstraction**: [lib/ai/llm_provider.py](file:///c:/Users/Vicky/Downloads/waymap-main_2/lib/ai/llm_provider.py)
  - Supports Cerebras, OpenAI, Anthropic, Ollama
  - Cerebras model fallback and rate limiting
  - Configuration via secrets.json and env vars

- **2. Result Analyzer**: [lib/ai/result_analyzer.py](file:///c:/Users/Vicky/Downloads/waymap-main_2/lib/ai/result_analyzer.py)
  - Analyzes vulnerabilities to explain severity, impact, and remediation
  - Provides false positive likelihood and confidence scores
  - Structured JSON output with validation

- **3. CLI & Interactive Integration**:
  - `--use-ai`, `--analyze`, `--ai-report` flags
  - Interactive mode asks "Would you like to use AI features?"
  - Auto-skips crawl if all targets have parameters

- **4. Logging & Feedback**:
  - Detailed AI processing logs and terminal output
  - Clear success/failure messages for AI operations
  - AI analysis printed to terminal after scan

---

### 📝 Next Priorities

#### Priority 1: Context-Aware Payload Generator
Create `lib/ai/payload_generator.py`
- Analyze initial test requests
- Observe WAF behavior
- Generate context-specific payloads
- Fall back to static payloads if needed

#### Priority 2: Attack Surface Discovery
Create `lib/ai/attack_surface.py`
- Analyze crawled HTML/JS
- Suggest endpoints and parameters
- Integrate with crawler

#### Priority 3: Multi-Step Attack Planner
Create `lib/ai/attack_planner.py`
- Reason across multiple observations
- Plan iterative test sequences
- Integrate with scan flow

#### Priority 4: Finding Chaining
Enhance `lib/ai/result_analyzer.py`
- Analyze all findings together
- Suggest possible chaining opportunities
- Document chains in reports

---

## Proposed Features (Full Plan)

### 1. Intelligent Result Analysis & Triage ✅ (Implemented)
**Use Case**: Automatically analyze scan results to prioritize vulnerabilities, explain impact, and suggest fixes.

**Implementation**:
- Module: [lib/ai/result_analyzer.py](file:///c:/Users/Vicky/Downloads/waymap-main_2/lib/ai/result_analyzer.py)
- Configurable LLM providers
- Returns structured JSON with:
  - Severity justification
  - Impact explanation
  - Remediation steps
  - False positive likelihood (0-1)
  - Confidence score (0-1)
- Stores analysis in `ResultManager`

**Hallucination Guardrails**:
- Structured output (JSON schema)
- Low temperature (0.2)
- Confidence score field; flag low-confidence results

---

### 2. Adaptive Payload Generation 📝 (Next)
**Use Case**: Generate payloads tailored to target context instead of using static lists.

**Implementation Plan**:
- Create `lib/ai/payload_generator.py`
- Use initial static payloads to establish baseline
- For parameterized URLs:
  - Send initial test requests to gather response patterns
  - Analyze WAF behavior (blocked requests, response codes)
  - Generate context-aware payload variations
- Add `--ai-payloads` flag
- Integrate with injection modules

**Hallucination Guardrails**:
- Validate payloads against safe syntax rules
- Test incrementally; only use verifiable payloads
- Hard limits on payload length/complexity
- Fall back to static payloads if AI fails

---

### 3. Enhanced Report Generation 📝 (Next)
**Use Case**: Generate human-readable, detailed reports with AI-written explanations.

**Implementation Plan**:
- Extend `ReportGenerator` with AI capabilities
- Add `--ai-report` flag
- For each vulnerability:
  - LLM writes plain-language description
  - Generate executive summary (audience-specific)
  - Add remediation checklist
- Keep AI content separate from core data

**Hallucination Guardrails**:
- All AI content labeled "AI-Generated"
- Technical details pulled directly from scan results
- LLM only summarizes and explains, never invents

---

### 4. False Positive Reduction 📝 (Later)
**Use Case**: Verify detected vulnerabilities to reduce false positives.

**Implementation Plan**:
- Create `lib/ai/false_positive_checker.py`
- For each vulnerability:
  - Pass full request/response pair
  - Evaluate true positive likelihood
  - Provide confidence and reasoning
- Add `--verify` flag
- Auto-mark potential false positives for review

**Hallucination Guardrails**:
- Require specific evidence from response
- Use multiple LLM calls to cross-verify
- Never auto-dismiss vulnerabilities

---

### 5. Smarter Crawling & Discovery 📝 (Later)
**Use Case**: Analyze page content to find hidden endpoints, parameters, or attack surfaces.

**Implementation Plan**:
- Create `lib/ai/crawler_enhancer.py`
- Integrate with existing crawler
- For each crawled page:
  - Analyze HTML/JS for hidden forms/API calls
  - Extract potential parameter names
  - Suggest additional URLs to scan
- Add `--ai-crawl` flag

**Hallucination Guardrails**:
- Only suggest endpoints/parameters appearing in actual content
- Validate all suggestions by checking source
- Prioritize based on confidence

---

### 6. Multi-Step Attack Planner 📝 (Later)
**Use Case**: Reason across multiple observations and plan iterative attacks.

**Implementation Plan**:
- Create `lib/ai/attack_planner.py`
- Observes responses across multiple test payloads
- Plans next payloads/tests based on patterns
- Integrates into scan flow for iterative testing

---

### 7. Finding Chaining 📝 (Later)
**Use Case**: Identify potential vulnerability chains from scan results.

**Implementation Plan**:
- Enhance result analyzer to consider all findings together
- Suggest possible chains with probability scores
- Document chains in AI-enhanced reports

---

## Technical Architecture

### Directory Structure
```
lib/ai/
├── __init__.py
├── llm_provider.py        # Abstract base class + concrete providers ✅
├── result_analyzer.py     # Feature 1: Result analysis ✅
├── payload_generator.py   # Feature 2: Payload generation 📝
├── report_enhancer.py     # Feature 3: Enhanced reports 📝
├── false_positive.py      # Feature 4: False positive checking 📝
├── crawler_enhancer.py    # Feature 5: Crawler enhancement 📝
├── attack_planner.py      # Feature 6: Multi-step planning 📝
└── chain_analyzer.py      # Feature 7: Finding chaining 📝
```

### Configuration
`config/waymap/secrets.example.json`:
```json
{
  "searchapi_api_key": "...",
  "wpscan_api_token": "...",
  "llm": {
    "provider": "cerebras",
    "api_key": "...",
    "model": "gpt-oss-120b",
    "temperature": 0.2,
    "max_tokens": 1000,
    "base_url": ""
  }
}
```

---

## Model Limits & Fallback Strategy

### Cerebras Model Limits
| Model | RPM | TPM | TPH | TPD |
|-------|-----|-----|-----|-----|
| gpt-oss-120b | 5 | 30K | 1M | 1M |
| zai-glm-4.7 | 5 | 30K | 1M | 1M |
| gemma-4-31b | 5 | 30K | 1M | 1M |

### Fallback Logic
- Priority Order: gpt-oss-120b → zai-glm-4.7 → gemma-4-31b
- Per-model rate limiting
- Auto-fallback on failure

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Hallucination | Structured output, low temperature, validation, human review |
| Cost | Usage limits, local LLM option, toggleable features |
| Privacy | Local LLM option, explicit consent, no sensitive data sent |
| Performance | Async LLM calls, caching, optional features |
| Reliability | Fallback to non-AI behavior, error handling |
| Over-Reliance | AI is only an assistant; deterministic engine owns verification |

---

## Next Steps
1. **Implement Adaptive Payload Generation** (Priority 1)
2. **Implement Attack Surface Discovery** (Priority 2)
3. **Implement Multi-Step Attack Planner** (Priority 3)
4. **Implement Finding Chaining** (Priority 4)
5. Test with real targets
6. Gather feedback and iterate
