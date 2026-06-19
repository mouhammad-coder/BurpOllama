"""
schema_parser.py — Auto-Ingestion of API Schemas
Turns passive Swagger/OpenAPI/GraphQL discoveries into active attack surfaces.
Found in Phase 1/Class 4 → parsed → URL list injected back into Phase 2.
"""

import asyncio
import json
import re
import httpx
from urllib.parse import urljoin, urlparse
from typing import Callable, Optional

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept":     "application/json, */*",
}
TIMEOUT = httpx.Timeout(12.0)

# ── OpenAPI / Swagger Parser ──────────────────────────────────────────────────

SWAGGER_PATHS = [
    "/api/swagger.json", "/api/swagger.yaml", "/swagger.json",
    "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api/v1/swagger.json", "/api/v2/swagger.json", "/api/v3/swagger.json",
    "/api-docs", "/api-docs.json", "/v1/api-docs", "/v2/api-docs",
    "/api/openapi", "/docs/api.json", "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
]

# HTTP methods worth actively fuzzing
FUZZ_METHODS = {"get", "post", "put", "patch", "delete"}

# Parameter locations to extract
PARAM_LOCATIONS = {"query", "path", "header", "body"}


def _extract_base_url(host_url: str, servers: list) -> str:
    """Extract base URL from OpenAPI servers block or fall back to host."""
    if servers:
        first = servers[0]
        if isinstance(first, dict):
            url = first.get("url", "")
            if url.startswith("http"):
                return url.rstrip("/")
            # Relative server URL
            parsed = urlparse(host_url)
            return "{}://{}{}".format(parsed.scheme, parsed.netloc, url.rstrip("/"))
    parsed = urlparse(host_url)
    return "{}://{}".format(parsed.scheme, parsed.netloc)


def _fill_path_params(path: str, params: list) -> tuple:
    """
    Replace path parameters with test values.
    /users/{id}/orders/{order_id} → /users/1/orders/1
    Returns (filled_path, param_names_used)
    """
    param_names = re.findall(r'\{([^}]+)\}', path)
    filled = path
    for pname in param_names:
        # Choose test value based on parameter name
        pname_lower = pname.lower()
        if any(k in pname_lower for k in ["id", "uid", "key", "num", "count"]):
            val = "1"
        elif any(k in pname_lower for k in ["name", "slug", "user", "account"]):
            val = "test"
        elif any(k in pname_lower for k in ["date", "time", "from", "to"]):
            val = "2024-01-01"
        else:
            val = "1"
        filled = filled.replace("{" + pname + "}", val)
    return filled, param_names


def _build_query_string(parameters: list) -> str:
    """Build a query string with test values from OpenAPI parameter definitions."""
    parts = []
    for p in parameters:
        if not isinstance(p, dict):
            continue
        loc  = p.get("in", "")
        name = p.get("name", "")
        if loc != "query" or not name:
            continue
        schema = p.get("schema", {}) or {}
        ptype  = schema.get("type", p.get("type", "string"))
        if ptype == "integer":
            val = "1"
        elif ptype == "boolean":
            val = "true"
        elif ptype == "array":
            val = "test"
        else:
            val = "test"
        parts.append("{}={}".format(name, val))
    return "&".join(parts)


def parse_openapi_schema(schema: dict, base_url: str) -> list:
    """
    Parse an OpenAPI 2.0 (Swagger) or 3.0 schema dict.
    Returns list of dicts: {url, method, params, description}
    """
    endpoints = []

    # Determine OpenAPI version
    version = schema.get("openapi", schema.get("swagger", "2.0"))
    is_v3   = str(version).startswith("3")

    # Base URL
    if is_v3:
        servers   = schema.get("servers", [])
        api_base  = _extract_base_url(base_url, servers)
    else:
        # Swagger 2.0
        host     = schema.get("host", urlparse(base_url).netloc)
        basepath = schema.get("basePath", "/")
        scheme   = schema.get("schemes", ["https"])[0]
        api_base = "{}://{}{}".format(scheme, host, basepath.rstrip("/"))

    paths = schema.get("paths", {})
    if not paths:
        return []

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        for method, operation in methods.items():
            if method.lower() not in FUZZ_METHODS:
                continue
            if not isinstance(operation, dict):
                continue

            # Extract parameters
            params = operation.get("parameters", []) or []
            # Merge path-level params
            path_params = methods.get("parameters", []) or []
            all_params  = path_params + params

            # Fill path parameters
            filled_path, path_param_names = _fill_path_params(path, all_params)
            qs = _build_query_string(all_params)

            full_url = api_base + filled_path
            if qs:
                full_url += "?" + qs

            # Extract request body schema for POST/PUT/PATCH
            body_example = {}
            body_content_type = ""
            if is_v3 and method.lower() in {"post", "put", "patch"}:
                rb = operation.get("requestBody", {})
                ct = rb.get("content", {})
                js = ct.get("application/json", {})
                body_schema = js.get("schema", {})
                if body_schema:
                    body_example = _generate_body_from_schema(body_schema)
                    body_content_type = "application/json"
            elif not is_v3 and method.lower() in {"post", "put", "patch"}:
                body_param = next(
                    (
                        parameter for parameter in all_params
                        if isinstance(parameter, dict)
                        and parameter.get("in") == "body"
                        and isinstance(parameter.get("schema"), dict)
                    ),
                    None,
                )
                if body_param:
                    body_example = _generate_body_from_schema(body_param["schema"])
                    consumes = operation.get("consumes") or schema.get("consumes") or []
                    if "application/json" in consumes or not consumes:
                        body_content_type = "application/json"

            endpoints.append({
                "url":         full_url,
                "method":      method.upper(),
                "path":        path,
                "params":      [p.get("name", "") for p in all_params if isinstance(p, dict)],
                "body":        body_example,
                "content_type":body_content_type,
                "description": operation.get("summary", operation.get("description", "")),
                "source":      "openapi-schema",
                "tags":        operation.get("tags", []),
            })

    return endpoints



# ── Recursion depth limiter (v3.2) ────────────────────────────────────────────
# Maximum structural depth for recursive body generation.
# Exceeding this risks stack overflows on self-referential or deeply nested schemas.
_MAX_BODY_DEPTH = 3

def _scalar_fallback(prop_schema: dict) -> object:
    """
    Return a safe, typed scalar when depth limit is reached.
    Inspects the schema hint to return the most appropriate primitive.
    """
    ptype  = prop_schema.get("type", "string")
    fmt    = prop_schema.get("format", "")
    enum   = prop_schema.get("enum", [])

    if enum:
        return enum[0]   # use first allowed value — always valid
    if ptype in ("integer", "number"):
        return 1
    if ptype == "boolean":
        return True
    if ptype == "array":
        return []
    if ptype == "object":
        return {}        # truncated — do NOT recurse
    if fmt in ("date", "date-time"):
        return "2024-01-01"
    if fmt == "email":
        return "test@example.com"
    if fmt == "uri":
        return "https://example.com"
    return ""            # default: empty string for any unknown string type


def _generate_body_from_schema(schema: dict, depth: int = 0) -> object:
    """
    Recursively generate a mock JSON request body from a JSON Schema object.

    v3.2 depth guard:
      - Tracks current nesting level via the `depth` counter.
      - Once depth >= _MAX_BODY_DEPTH (3), the recursive branch is truncated
        and _scalar_fallback() provides a safe typed primitive instead of
        an empty dict. This prevents memory exhaustion on circular or
        deeply nested API schemas (e.g., JSON-API compound documents,
        recursive tree structures, or OpenAPI allOf/anyOf chains).
    """
    # ── Depth limit reached — return typed scalar, not empty dict ─────────────
    if depth >= _MAX_BODY_DEPTH:
        return _scalar_fallback(schema)

    # ── allOf / anyOf / oneOf — merge or pick first branch ───────────────────
    for combiner in ("allOf", "anyOf", "oneOf"):
        branches = schema.get(combiner, [])
        if branches and isinstance(branches, list):
            # Merge allOf; take first branch for anyOf/oneOf
            if combiner == "allOf":
                merged = {}
                for branch in branches:
                    if isinstance(branch, dict):
                        sub = _generate_body_from_schema(branch, depth)
                        if isinstance(sub, dict):
                            merged.update(sub)
                return merged
            else:
                first = branches[0]
                return _generate_body_from_schema(first, depth) if isinstance(first, dict) else ""

    # ── Object with properties ────────────────────────────────────────────────
    if schema.get("type") == "object" or "properties" in schema:
        result = {}
        properties = schema.get("properties") or {}
        for prop, prop_schema in properties.items():
            if not isinstance(prop_schema, dict):
                result[prop] = ""
                continue

            ptype = prop_schema.get("type", "string")

            if ptype == "object" or "properties" in prop_schema:
                # Recurse — depth+1 guards against infinite nesting
                result[prop] = _generate_body_from_schema(prop_schema, depth + 1)

            elif ptype == "array":
                # Generate one example item for the array
                items_schema = prop_schema.get("items", {})
                if isinstance(items_schema, dict) and items_schema:
                    example_item = _generate_body_from_schema(items_schema, depth + 1)
                    result[prop] = [example_item]
                else:
                    result[prop] = []

            else:
                result[prop] = _scalar_fallback(prop_schema)

        # Populate required fields with fallbacks if not already set
        for req in (schema.get("required") or []):
            if req not in result:
                result[req] = ""

        return result

    # ── Primitive / scalar schema ─────────────────────────────────────────────
    return _scalar_fallback(schema)


_VALIDATION_ERROR_KEYWORDS = (
    "validation error", "missing field", "missing required",
    "expected object", "required property", "invalid type",
    "bad request", "constraint violation", "schema error",
)


def _looks_like_validation_error(response_body: str) -> bool:
    """Return True if a 400 response body indicates schema depth truncation."""
    body_lower = response_body.lower()
    return any(kw in body_lower for kw in _VALIDATION_ERROR_KEYWORDS)


async def _retry_endpoint_with_deeper_schema(
    client:    httpx.AsyncClient,
    endpoint:  dict,
    schema:    dict,
    base_url:  str,
    log:       Callable,
) -> dict:
    """
    v3.3: If a schema-derived POST/PUT/PATCH returns 400 with validation
    keywords, re-parse the specific path with _MAX_BODY_DEPTH=5 and retry.
    Returns the endpoint dict with updated body and a retry_status field.
    """
    global _MAX_BODY_DEPTH
    orig_depth    = _MAX_BODY_DEPTH
    _MAX_BODY_DEPTH = 5

    path    = endpoint.get("path", "")
    method  = endpoint.get("method", "GET").lower()
    log("[Schema] Adaptive depth retry for {} {} (depth 3→5)".format(method.upper(), path))

    try:
        paths = schema.get("paths", {})
        if path in paths and method in paths[path]:
            operation   = paths[path][method]
            rb          = operation.get("requestBody", {})
            ct          = rb.get("content", {})
            js          = ct.get("application/json", {})
            body_schema = js.get("schema", {})
            if body_schema:
                new_body = _generate_body_from_schema(body_schema, depth=0)
                endpoint  = dict(endpoint)
                endpoint["body"]          = new_body
                endpoint["_depth_retried"] = True
    except Exception as e:
        log("[Schema] Depth retry parse error: {}".format(e))
    finally:
        _MAX_BODY_DEPTH = orig_depth

    return endpoint

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/graph"]

GQL_INTROSPECTION = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""


def parse_graphql_schema(introspection_response: dict, graphql_url: str) -> list:
    """
    Parse a GraphQL introspection response and generate valid queries/mutations
    for every queryable object type.
    Returns list of {url, method, gql_query, type_name, description}.
    """
    endpoints = []

    try:
        schema   = introspection_response.get("data", {}).get("__schema", {})
        if not schema:
            schema = introspection_response.get("__schema", {})

        types     = schema.get("types", [])
        q_type    = (schema.get("queryType")    or {}).get("name", "Query")
        m_type    = (schema.get("mutationType") or {}).get("name", "Mutation")

        # Build type map
        type_map = {t["name"]: t for t in types if isinstance(t, dict) and t.get("name")}

        # Generate queries for every field on Query type
        for root_type_name in [q_type, m_type]:
            if not root_type_name or root_type_name not in type_map:
                continue
            root_type = type_map[root_type_name]
            fields    = root_type.get("fields") or []
            is_mutation = (root_type_name == m_type)

            for field in fields:
                if not isinstance(field, dict):
                    continue
                fname  = field.get("name", "")
                if not fname:
                    continue

                args   = field.get("args", []) or []
                ftype  = field.get("type", {}) or {}

                # Build argument string with test values
                arg_str = _build_gql_args(args)

                # Build selection set from return type
                ret_type_name = _unwrap_gql_type(ftype)
                selection     = _build_gql_selection(ret_type_name, type_map)

                op_keyword = "mutation" if is_mutation else "query"
                query = "{} {{ {}{}{}  }}".format(
                    op_keyword,
                    fname,
                    "({})".format(arg_str) if arg_str else "",
                    " {{ {} }}".format(selection) if selection else "",
                )

                endpoints.append({
                    "url":         graphql_url,
                    "method":      "POST",
                    "gql_query":   query,
                    "type_name":   fname,
                    "is_mutation": is_mutation,
                    "description": "GraphQL {} {}".format(op_keyword, fname),
                    "source":      "graphql-schema",
                    "args":        [a.get("name", "") for a in args if isinstance(a, dict)],
                })

    except Exception as e:
        print("[SchemaParser] GraphQL parse error: {}".format(e))

    return endpoints


def _build_gql_args(args: list) -> str:
    """Build a GraphQL argument string with test values."""
    parts = []
    for arg in args:
        if not isinstance(arg, dict):
            continue
        name   = arg.get("name", "")
        t      = _unwrap_gql_type(arg.get("type", {}))
        if not name:
            continue
        if t in ("Int", "Float"):
            val = "1"
        elif t == "Boolean":
            val = "true"
        elif t == "ID":
            val = '"1"'
        else:
            val = '"test"'
        parts.append("{}: {}".format(name, val))
    return ", ".join(parts)


def _unwrap_gql_type(type_obj: dict, depth: int = 0) -> str:
    """Recursively unwrap a GraphQL type to get the base name."""
    if depth > 5 or not isinstance(type_obj, dict):
        return "String"
    name = type_obj.get("name")
    if name:
        return name
    of_type = type_obj.get("ofType")
    if of_type:
        return _unwrap_gql_type(of_type, depth + 1)
    return "String"


def _build_gql_selection(type_name: str, type_map: dict, depth: int = 0) -> str:
    """Build a selection set for a GraphQL type (max 2 levels deep)."""
    if depth > 1 or not type_name or type_name not in type_map:
        return ""
    t = type_map[type_name]
    if t.get("kind") not in ("OBJECT", "INTERFACE"):
        return ""
    fields = t.get("fields") or []
    # Take scalar/simple fields only to avoid infinite recursion
    scalar_names = []
    for f in fields[:8]:
        if not isinstance(f, dict):
            continue
        ft = _unwrap_gql_type(f.get("type", {}))
        if ft in ("String", "Int", "Float", "Boolean", "ID") or not ft:
            scalar_names.append(f.get("name", ""))
    return " ".join(s for s in scalar_names if s)


# ── Master schema ingester ────────────────────────────────────────────────────

async def ingest_schemas(
    live_hosts:   list,
    known_swagger: list,
    known_graphql: list,
    log:          Callable,
) -> dict:
    """
    Try to fetch and parse API schemas from discovered endpoints.

    known_swagger: list of URLs where Swagger/OpenAPI was found (from Class 4)
    known_graphql: list of URLs where GraphQL introspection is open (from Class 12)

    Returns {
      "openapi_endpoints": [...],
      "graphql_endpoints": [...],
      "all_urls":          [...],  ← inject these back into Phase 2
      "schemas_found":     int,
    }
    """
    result = {
        "openapi_endpoints": [],
        "graphql_endpoints": [],
        "graphql_schemas":   [],
        "all_urls":          [],
        "schemas_found":     0,
    }

    async with httpx.AsyncClient(
        headers=HEADERS, verify=False,
        follow_redirects=True, timeout=TIMEOUT,
    ) as client:

        # ── OpenAPI / Swagger ──────────────────────────────────────────────
        swagger_urls_to_try = list(known_swagger)

        # Also probe standard paths on each live host
        for h in live_hosts[:10]:
            base = "{}://{}".format(
                urlparse(h["url"]).scheme, urlparse(h["url"]).netloc
            )
            for path in SWAGGER_PATHS:
                swagger_urls_to_try.append(base + path)

        seen_schemas = set()
        for swagger_url in swagger_urls_to_try:
            try:
                r = await client.get(swagger_url)
                if r.status_code != 200:
                    continue
                ct = r.headers.get("content-type", "")
                if "json" not in ct and not swagger_url.endswith((".json", ".yaml")):
                    continue

                schema = r.json()
                # Validate it looks like OpenAPI
                if not (schema.get("paths") or schema.get("swagger") or schema.get("openapi")):
                    continue

                schema_key = str(sorted(schema.get("paths", {}).keys())[:5])
                if schema_key in seen_schemas:
                    continue
                seen_schemas.add(schema_key)

                log("[Schema] Parsing OpenAPI schema from: {}".format(swagger_url))
                endpoints = parse_openapi_schema(schema, swagger_url)
                result["openapi_endpoints"].extend(endpoints)
                result["schemas_found"] += 1
                log("[Schema] Extracted {} endpoints from OpenAPI schema".format(len(endpoints)))

            except Exception as e:
                pass

        # ── GraphQL ───────────────────────────────────────────────────────
        graphql_urls_to_try = list(known_graphql)
        for h in live_hosts[:10]:
            base = "{}://{}".format(
                urlparse(h["url"]).scheme, urlparse(h["url"]).netloc
            )
            for path in GRAPHQL_PATHS:
                graphql_urls_to_try.append(base + path)

        for gql_url in list(set(graphql_urls_to_try)):
            try:
                r = await client.post(
                    gql_url,
                    content=json.dumps({"query": GQL_INTROSPECTION}),
                    headers={**HEADERS, "Content-Type": "application/json"},
                )
                if r.status_code != 200:
                    continue
                data = r.json()
                if "__schema" not in str(data):
                    continue

                log("[Schema] Parsing GraphQL introspection from: {}".format(gql_url))
                gql_endpoints = parse_graphql_schema(data, gql_url)
                result["graphql_endpoints"].extend(gql_endpoints)
                result["graphql_schemas"].append({
                    "url": gql_url,
                    "schema": data,
                })
                result["schemas_found"] += 1
                log("[Schema] Generated {} GraphQL queries from schema".format(len(gql_endpoints)))

            except Exception:
                pass

    # Collect all generated URLs for injection into Phase 2
    for ep in result["openapi_endpoints"]:
        result["all_urls"].append(ep["url"])
    for ep in result["graphql_endpoints"]:
        result["all_urls"].append(ep["url"])

    log("[Schema] Total schema-derived URLs injected into hunt: {}".format(
        len(result["all_urls"])))

    return result
