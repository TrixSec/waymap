"""GraphQL security checks suite."""

import json
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from lib.recon.common import build_url, get_domain, normalize_target, now_iso, request_url, save_and_report
from lib.ui import print_header, print_status

COMMON_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/graphql/api",
    "/gql",
    "/api/gql",
]

INTROSPECTION_QUERY = {
    "query": "query IntrospectionQuery { __schema { types { name kind } } }"
}

TYPENAME_QUERY = {"query": "query { __typename }"}

DEPTH_QUERY = {
    "query": "query DepthTest { __schema { types { name fields { name type { name kind } } } } }"
}

BATCH_QUERY = [
    {"query": "query { __typename }"},
    {"query": "query { __schema { queryType { name } } }"},
]

SUBSCRIPTION_QUERY = {"query": "subscription { __typename }"}


def _candidate_endpoints(urls: List[str]) -> List[str]:
    endpoints: Set[str] = set()
    for url in urls:
        parsed = urlparse(url)
        if "graphql" in parsed.path.lower():
            endpoints.add(f"{parsed.scheme}://{parsed.netloc}{parsed.path}")

    if not endpoints and urls:
        base = normalize_target(urls[0])
        for path in COMMON_GRAPHQL_PATHS:
            endpoints.add(build_url(base, path))

    return sorted(endpoints)


def _post_json(url: str, payload: Any) -> Optional[Dict[str, Any]]:
    headers = {"Content-Type": "application/json"}
    response = request_url(url, method="POST", headers=headers, json=payload)
    if not response:
        return None

    try:
        return response.json()
    except Exception:
        return {"raw": response.text, "status": response.status_code}


def _is_graphql_response(data: Dict[str, Any]) -> bool:
    if not isinstance(data, dict):
        return False
    if "data" in data or "errors" in data:
        return True
    if "raw" in data and ("errors" in str(data["raw"]) or "data" in str(data["raw"])):
        return True
    return False


def perform_graphql_suite_scan(urls: List[str], verbose: bool = False) -> None:
    if not urls:
        print_status("No URLs provided for GraphQL suite", "warning")
        return

    print_header("GraphQL Suite", color="cyan")

    endpoints = _candidate_endpoints(urls)
    if not endpoints:
        print_status("No GraphQL endpoints detected", "warning")
        return

    base_domain = get_domain(endpoints[0])

    for endpoint in endpoints:
        discovery_resp = request_url(endpoint, method="GET")
        if discovery_resp and discovery_resp.status_code not in {404, 405}:
            save_and_report(
                base_domain,
                "graphql_endpoint_discovery",
                {
                    "url": endpoint,
                    "timestamp": now_iso(),
                    "status": str(discovery_resp.status_code),
                },
                unique_keys=["url", "status"],
            )

        introspection = _post_json(endpoint, INTROSPECTION_QUERY)
        if introspection and _is_graphql_response(introspection) and "__schema" in json.dumps(introspection):
            save_and_report(
                base_domain,
                "graphql_introspection_exposure",
                {
                    "url": endpoint,
                    "timestamp": now_iso(),
                },
                unique_keys=["url"],
            )
            save_and_report(
                base_domain,
                "graphql_schema_dump_checks",
                {
                    "url": endpoint,
                    "timestamp": now_iso(),
                },
                unique_keys=["url"],
            )

        typename = _post_json(endpoint, TYPENAME_QUERY)
        if typename and _is_graphql_response(typename) and "data" in typename:
            save_and_report(
                base_domain,
                "graphql_unauthenticated_access",
                {
                    "url": endpoint,
                    "timestamp": now_iso(),
                },
                unique_keys=["url"],
            )

        depth = _post_json(endpoint, DEPTH_QUERY)
        if depth and _is_graphql_response(depth) and "errors" not in depth:
            save_and_report(
                base_domain,
                "graphql_depth_limit_checks",
                {
                    "url": endpoint,
                    "timestamp": now_iso(),
                },
                unique_keys=["url"],
            )
            save_and_report(
                base_domain,
                "graphql_query_complexity_checks",
                {
                    "url": endpoint,
                    "timestamp": now_iso(),
                },
                unique_keys=["url"],
            )

        batch_resp = _post_json(endpoint, BATCH_QUERY)
        if batch_resp and isinstance(batch_resp, list):
            save_and_report(
                base_domain,
                "graphql_batching_checks",
                {
                    "url": endpoint,
                    "timestamp": now_iso(),
                },
                unique_keys=["url"],
            )

        subscription_resp = _post_json(endpoint, SUBSCRIPTION_QUERY)
        if subscription_resp and _is_graphql_response(subscription_resp) and "errors" not in subscription_resp:
            save_and_report(
                base_domain,
                "graphql_subscription_checks",
                {
                    "url": endpoint,
                    "timestamp": now_iso(),
                },
                unique_keys=["url"],
            )

    print_status("GraphQL suite completed", "info")
