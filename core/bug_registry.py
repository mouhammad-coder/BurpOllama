"""Central bug type registry for final finding classification.

The registry is intentionally descriptive. Agents can emit lightweight
dictionaries, while the proof validator and final presenter use these rules to
decide whether an item is a Great Finding, Needs Manual Check, Informational,
or Rejected.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


RATES = ("Critical", "High", "Medium", "Low", "Info")
STATUSES = ("Great Finding", "Needs Manual Check", "Informational", "Rejected")


@dataclass(frozen=True)
class BugType:
    id: str
    name: str
    category: str
    default_rate: str
    minimum_evidence_for_great: str
    needs_manual_check_when: tuple[str, ...]
    common_false_positives: tuple[str, ...]
    safe_automated_checks: tuple[str, ...]
    unsafe_checks: tuple[str, ...]
    required_manual_verification: tuple[str, ...]
    impact_template: str

    def to_dict(self) -> dict:
        return asdict(self)


def _bug(
    bug_id: str,
    name: str,
    category: str,
    default_rate: str,
    great: str,
    manual: tuple[str, ...],
    fp: tuple[str, ...],
    safe: tuple[str, ...],
    unsafe: tuple[str, ...],
    verify: tuple[str, ...],
    impact: str,
) -> BugType:
    if default_rate not in RATES:
        raise ValueError(f"Invalid default rate for {bug_id}: {default_rate}")
    def tupled(value):
        if isinstance(value, tuple):
            return value
        if isinstance(value, list):
            return tuple(str(item) for item in value if str(item).strip())
        text = str(value or "").strip()
        return (text,) if text else ()

    return BugType(
        id=bug_id,
        name=name,
        category=category,
        default_rate=default_rate,
        minimum_evidence_for_great=great,
        needs_manual_check_when=tupled(manual),
        common_false_positives=tupled(fp),
        safe_automated_checks=tupled(safe),
        unsafe_checks=tupled(unsafe),
        required_manual_verification=tupled(verify),
        impact_template=impact,
    )


def _standard_manual(*extra: str) -> tuple[str, ...]:
    return (
        "Evidence is partial or inferred from surface discovery.",
        "Impact cannot be confirmed safely without human validation.",
        "Authorized credentials, role comparison, or program permission is missing.",
        *extra,
    )


BUG_TYPES: dict[str, BugType] = {
    item.id: item
    for item in (
        _bug("idor", "IDOR", "Access Control", "High", "Two authorized users show an object ownership mismatch in request/response evidence.", _standard_manual("Needs two authorized accounts."), ("Sequential IDs alone.", "Unauthenticated public resource."), ("Detect object ID patterns.", "Compare safe controlled-account responses when supplied."), ("Accessing real user data.", "Changing object state without permission."), ("Verify with two authorized test accounts."), "Possible unauthorized access to another user's object."),
        _bug("bola", "BOLA", "Access Control", "High", "Controlled user A can read or modify controlled user B's API object.", _standard_manual("Requires role or user comparison."), ("Numeric IDs without authorization context.",), ("Identify object routes.",), ("Testing against non-owned objects.",), ("Test with two authorized accounts."), "Broken object authorization may expose sensitive API data."),
        _bug("broken_function_level_authorization", "Broken Function Level Authorization", "Access Control", "High", "Lower-privileged test account reaches a privileged function.", _standard_manual("Requires role comparison."), ("Login page for admin area.",), ("Detect privileged routes.",), ("Privilege escalation attempts outside test roles.",), ("Compare low and high privilege test roles."), "A user may access functionality outside their role."),
        _bug("admin_page_exposure", "Admin page exposure", "Access Control", "Medium", "Admin route is reachable and exposes sensitive functionality or data.", _standard_manual("Need auth-state and impact confirmation."), ("Admin login page only.",), ("Detect admin surfaces.",), ("Bypassing authentication controls.",), ("Confirm whether sensitive admin functions are accessible."), "Exposed admin surfaces may enable unauthorized management actions."),
        _bug("role_bypass_candidate", "Role bypass candidate", "Access Control", "High", "Role boundary bypass is reproduced with controlled roles.", _standard_manual("Requires business role understanding."), ("Role names in JS only.",), ("Map role-related endpoints.",), ("Manipulating production roles.",), ("Compare authorized roles in a test tenant."), "Role bypass can expose privileged workflows."),
        _bug("unauthenticated_sensitive_resource", "Unauthenticated access to protected resource", "Access Control", "High", "Sensitive protected data is returned without credentials.", _standard_manual("Need sensitivity and expected-auth confirmation."), ("Public documentation endpoint.",), ("Check unauthenticated response status and content hints.",), ("Accessing personal data.",), ("Confirm resource is intended to require auth."), "Protected resources available without auth can leak sensitive data."),
        _bug("horizontal_privilege_candidate", "Horizontal privilege issue candidate", "Access Control", "High", "Controlled peer-account access succeeds.", _standard_manual("Needs peer account comparison."), ("Object ID guess only.",), ("Detect peer object patterns.",), ("Testing real accounts.",), ("Use two authorized peer accounts."), "Horizontal privilege issues may expose another user's records."),
        _bug("vertical_privilege_candidate", "Vertical privilege issue candidate", "Access Control", "High", "Lower role reaches higher role data or action.", _standard_manual("Needs role comparison."), ("Admin URL discovered only.",), ("Detect role-gated route patterns.",), ("Privilege-changing actions.",), ("Use authorized lower and higher role accounts."), "Vertical privilege issues can grant administrative access."),
        _bug("weak_session_cookie_impact", "Weak session cookie configuration with impact", "Authentication and Session", "Medium", "Cookie weakness is tied to a concrete exploitable flow or sensitive session context.", _standard_manual("Missing impact context."), ("Missing flag on non-session cookie.",), ("Inspect Set-Cookie safely.",), ("Session theft simulation.",), ("Confirm cookie purpose and impact."), "Weak session cookie controls may aid account compromise."),
        _bug("insecure_logout", "Insecure logout behavior", "Authentication and Session", "Medium", "Session remains usable after logout in controlled testing.", _standard_manual("Needs authenticated cookie and logout flow."), ("Cached page after logout.",), ("Observe logout endpoints.",), ("Reusing real user sessions.",), ("Test with a disposable authorized account."), "Logout failure can keep sessions alive unexpectedly."),
        _bug("session_fixation_candidate", "Session fixation candidate", "Authentication and Session", "High", "Session token remains fixed across login in controlled evidence.", _standard_manual("Needs authenticated flow proof."), ("Static CSRF token mistaken for session.",), ("Compare pre/post-login cookie names.",), ("Hijacking or setting victim sessions.",), ("Use a disposable account to compare session rotation."), "Session fixation can let an attacker bind a victim to a known session."),
        _bug("missing_auth_sensitive_endpoint", "Missing auth on sensitive endpoint", "Authentication and Session", "High", "Endpoint returns sensitive action/data without auth.", _standard_manual("Need expected-auth and sensitivity proof."), ("Public health/status endpoints.",), ("Check unauthenticated status and content class.",), ("Calling state-changing actions.",), ("Confirm endpoint sensitivity with program context."), "Missing auth can expose protected functionality."),
        _bug("password_reset_flow_candidate", "Password reset flow weakness candidate", "Authentication and Session", "High", "Safe controlled proof shows reset token, account, or redirect weakness.", _standard_manual("Requires account ownership and workflow validation."), ("Reset endpoint exists.",), ("Map reset flow URLs.",), ("Resetting accounts without permission.",), ("Test only on owned accounts."), "Password reset weaknesses may lead to account takeover."),
        _bug("account_enumeration_candidate", "Account enumeration candidate", "Authentication and Session", "Low", "Response difference is reproducible and useful for account discovery.", _standard_manual("Needs safe controlled identifier set."), ("Generic timing noise.",), ("Compare low-rate response messages.",), ("High-volume enumeration.",), ("Confirm program accepts enumeration reports."), "Enumeration can support targeted attacks."),
        _bug("mfa_bypass_candidate", "MFA bypass candidate", "Authentication and Session", "High", "Controlled evidence shows MFA can be bypassed safely.", _standard_manual("MFA bypass is manual-check unless strong safe proof exists."), ("MFA setup page discovered.",), ("Map MFA endpoints.",), ("Bypassing real MFA protections.",), ("Validate with owned accounts and program permission."), "MFA bypass can undermine account protection."),
        _bug("sensitive_api_endpoint", "Sensitive API endpoint exposure", "API", "Medium", "Sensitive API data is reachable and evidenced.", _standard_manual("Need auth and sensitivity context."), ("API route listed in JS only.",), ("Catalog endpoints from JS and crawler data.",), ("Querying non-owned data.",), ("Confirm endpoint data sensitivity."), "Exposed APIs can leak sensitive application data."),
        _bug("excessive_data_exposure", "Excessive data exposure", "API", "High", "Response contains unnecessary sensitive fields from controlled data.", _standard_manual("Needs response body and field sensitivity proof."), ("Benign metadata fields.",), ("Inspect controlled response snippets.",), ("Collecting personal data.",), ("Use owned records and redact personal data."), "Excessive fields can expose sensitive information."),
        _bug("mass_assignment_candidate", "Mass assignment candidate", "API", "High", "A controlled forbidden field update is accepted.", _standard_manual("Requires active update permission."), ("Field name present in JS.",), ("Identify writable object schemas.",), ("Changing production state.",), ("Use disposable test object if allowed."), "Mass assignment may let users change protected fields."),
        _bug("object_id_pattern_risk", "Object ID pattern risk", "API", "Medium", "Object IDs are predictable and tied to sensitive object routes.", _standard_manual("Needs access-control proof."), ("Sequential IDs on public resources.",), ("Detect predictable identifiers.",), ("Testing real objects.",), ("Pair with authorized access-control comparison."), "Predictable IDs can support authorization attacks."),
        _bug("unsafe_cors_impact", "Unsafe CORS with impact", "API", "High", "Credentials and attacker-controlled origin are allowed on sensitive endpoint.", _standard_manual("Need credentialed impact proof."), ("Wildcard CORS without credentials.",), ("Inspect CORS headers.",), ("Stealing tokens or real data.",), ("Confirm with owned session and safe origin."), "Unsafe CORS can expose authenticated data cross-origin."),
        _bug("error_disclosure_impact", "Improper error disclosure with impact", "API", "Low", "Error reveals sensitive internals useful for exploitation.", _standard_manual("Need sensitive content proof."), ("Generic stack-like wording.",), ("Observe error responses.",), ("Triggering destructive errors.",), ("Confirm leaked data is sensitive and in scope."), "Verbose errors can reveal implementation details or secrets."),
        _bug("api_version_exposure", "API version exposure with risk context", "API", "Info", "Deprecated version is linked to known sensitive behavior.", _standard_manual("Usually informational without impact."), ("Version string only.",), ("Catalog versions.",), ("Exploiting known CVEs without permission.",), ("Confirm deprecated version is reachable and risky."), "Old API versions may expose weaker controls."),
        _bug("graphql_endpoint", "Exposed GraphQL endpoint", "GraphQL", "Info", "Endpoint is reachable with sensitive schema or auth weakness evidence.", _standard_manual("Endpoint discovery alone is informational."), ("GraphQL landing page only.",), ("Detect endpoint and safe errors.",), ("Unauthorized introspection if disallowed.",), ("Check program rules before introspection."), "GraphQL endpoints can concentrate sensitive data access."),
        _bug("graphql_introspection_allowed", "Introspection allowed if permitted", "GraphQL", "Medium", "Introspection returns schema and program permits this check.", _standard_manual("Requires program permission."), ("Public schema intentionally exposed.",), ("Send one bounded introspection query only when allowed.",), ("Introspection where rules forbid it.",), ("Confirm policy accepts introspection findings."), "Schema exposure can accelerate attack discovery."),
        _bug("graphql_auth_candidate", "Weak GraphQL authorization candidate", "GraphQL", "High", "Controlled role/user query shows unauthorized GraphQL data.", _standard_manual("Needs role/user comparison."), ("Field names in schema only.",), ("Map sensitive fields.",), ("Querying real records.",), ("Test with owned users and roles."), "Weak GraphQL authorization can expose cross-user data."),
        _bug("graphql_schema_exposure", "Excessive schema exposure", "GraphQL", "Low", "Schema exposes sensitive operations with risk context.", _standard_manual("Need sensitive operation context."), ("Normal public schema.",), ("Review schema names.",), ("Invoking mutations.",), ("Confirm sensitive operations and program stance."), "Schema disclosure may reveal privileged workflows."),
        _bug("graphql_error_leakage", "GraphQL error leakage", "GraphQL", "Low", "Errors reveal sensitive internals.", _standard_manual("Need leaked sensitive detail."), ("Generic GraphQL validation errors.",), ("Observe safe malformed query errors.",), ("Forcing server errors.",), ("Confirm leaked detail is meaningful."), "GraphQL errors can disclose internals."),
        _bug("graphql_batching_rate", "GraphQL batching/rate concern", "GraphQL", "Medium", "Batching concern is observed without high-volume testing.", _standard_manual("Rate validation requires permission."), ("Batch support alone.",), ("Detect batching support with minimal request.",), ("High-volume batching.",), ("Check program rules before manual rate tests."), "Batching can amplify brute force or scraping if unbounded."),
        _bug("open_redirect_confirmed", "Open redirect confirmed", "Redirects", "Medium", "Controlled external redirect is confirmed with safe URL.", _standard_manual("Need program acceptance context."), ("Internal-only redirect.",), ("Use benign external URL and no tokens.",), ("Token leakage testing without permission.",), ("Confirm bounty program accepts open redirects."), "Open redirects can support phishing or token leakage chains."),
        _bug("open_redirect_candidate", "Open redirect candidate", "Redirects", "Medium", "Redirect parameter is present but external control is not proven.", _standard_manual("Needs controlled redirect confirmation."), ("Parameter named next but sanitized.",), ("Detect redirect-like parameters.",), ("Testing token-bearing flows.",), ("Try a benign external URL if allowed."), "Redirect parameters may become phishing or token leakage issues."),
        _bug("unsafe_redirect_param", "Unsafe next/returnUrl parameter", "Redirects", "Low", "Unvalidated redirect-like parameter has partial evidence.", _standard_manual("Needs behavior proof."), ("Unused parameter.",), ("Catalog redirect parameters.",), ("Forcing sensitive redirects.",), ("Confirm redirect behavior safely."), "Unsafe redirect parameters can route users to attacker-controlled sites."),
        _bug("external_redirect_behavior", "External redirect behavior", "Redirects", "Medium", "External redirect behavior is confirmed in a sensitive flow.", _standard_manual("Need flow sensitivity."), ("Marketing outbound links.",), ("Observe Location header.",), ("Token-bearing flow testing.",), ("Confirm sensitive context and program rules."), "External redirects in auth flows can leak tokens or aid phishing."),
        _bug("reflected_xss_candidate", "Reflected XSS candidate", "Injection", "High", "Safe marker reflects in executable context with bounded proof.", _standard_manual("Needs browser/context confirmation."), ("HTML reflection in escaped context.",), ("Use harmless marker payloads.",), ("Executing destructive scripts.",), ("Confirm execution context safely."), "Reflected XSS can execute attacker-controlled JavaScript."),
        _bug("stored_xss_candidate", "Stored XSS candidate", "Injection", "High", "Safe marker is stored and rendered in executable context on owned content.", _standard_manual("Requires active testing permission."), ("Stored text rendered escaped.",), ("Detect storage sinks from owned content.",), ("Posting to shared production content.",), ("Use disposable owned content if allowed."), "Stored XSS can affect users who view stored content."),
        _bug("dom_xss_candidate", "DOM XSS candidate", "Injection", "High", "JS sink and source are connected with safe reproducible proof.", _standard_manual("Needs browser execution confirmation."), ("Sink name present without source.",), ("Static JS sink/source detection.",), ("Malicious payload execution.",), ("Validate in a safe browser context."), "DOM XSS can execute client-side script from controlled input."),
        _bug("sql_injection_candidate", "SQL injection candidate", "Injection", "Critical", "Safe error or boolean proof shows database query control.", _standard_manual("No destructive payloads; proof may require manual validation."), ("Generic 500 errors.",), ("Use bounded harmless probes.",), ("Data extraction, stacked queries, destructive writes.",), ("Confirm impact with safe payloads only."), "SQL injection can expose or modify database records."),
        _bug("command_injection_candidate", "Command injection candidate", "Injection", "Critical", "Safe command marker or controlled benign timing proof is observed.", _standard_manual("Requires strict permission and safe proof."), ("Generic timeout.",), ("Use non-destructive markers only.",), ("Arbitrary shell execution.",), ("Validate only if explicitly authorized."), "Command injection can lead to server compromise."),
        _bug("template_injection_candidate", "Template injection candidate", "Injection", "High", "Safe arithmetic marker is evaluated by template engine.", _standard_manual("Needs safe evaluation proof."), ("Reflected braces.",), ("Use harmless arithmetic markers.",), ("Reading files or executing commands.",), ("Confirm engine behavior safely."), "Template injection can lead to data exposure or code execution."),
        _bug("path_traversal_candidate", "Path traversal candidate", "Injection", "High", "Safe traversal proof reads only approved benign files or shows path normalization flaw.", _standard_manual("Unsafe proof must be manual."), ("File parameter exists.",), ("Use benign path markers.",), ("Reading sensitive system files.",), ("Confirm with program-approved file targets."), "Path traversal can expose server files."),
        _bug("header_injection_candidate", "Header injection candidate", "Injection", "High", "Safe header splitting marker is reflected in headers.", _standard_manual("Needs response header proof."), ("Header value echo without split.",), ("Use harmless CRLF markers if allowed.",), ("Cache poisoning or response smuggling.",), ("Confirm header behavior safely."), "Header injection can enable response splitting or cache attacks."),
        _bug("unrestricted_file_upload", "Unrestricted file upload candidate", "Uploads", "High", "A harmless controlled file type is accepted and served unsafely.", _standard_manual("Requires upload permission."), ("Upload form exists.",), ("Detect upload forms.",), ("Uploading executable or malicious files.",), ("Use benign files only when program allows uploads."), "Unrestricted upload can lead to stored XSS or server compromise."),
        _bug("dangerous_file_type_upload", "Dangerous file type accepted candidate", "Uploads", "High", "Dangerous extension is accepted in controlled safe test.", _standard_manual("Active upload not allowed yet."), ("Client-side accept list.",), ("Inspect form constraints.",), ("Uploading web shells or malware.",), ("Test only approved benign extensions."), "Dangerous file types may execute or expose users to attacks."),
        _bug("missing_content_type_validation", "Missing content-type validation candidate", "Uploads", "Medium", "Server accepts mismatched benign content type.", _standard_manual("Requires upload permission."), ("No enctype on form.",), ("Inspect upload requests.",), ("Uploading harmful content.",), ("Use benign test file if allowed."), "Weak upload validation can permit unsafe files."),
        _bug("upload_path_disclosure", "Upload path disclosure", "Uploads", "Low", "Response discloses server or public upload path.", _standard_manual("Need sensitivity context."), ("Normal public URL.",), ("Inspect upload responses.",), ("Uploading files without permission.",), ("Confirm path reveals sensitive internals."), "Upload path disclosure can aid exploitation."),
        _bug("public_uploaded_file_exposure", "Public uploaded file exposure candidate", "Uploads", "Medium", "Uploaded owned file is publicly accessible unexpectedly.", _standard_manual("Requires upload and access expectation proof."), ("Public avatar file by design.",), ("Detect public upload URL patterns.",), ("Accessing others' uploads.",), ("Confirm privacy expectation with owned file."), "Public uploads can leak private user content."),
        _bug("ssrf_candidate", "SSRF candidate", "SSRF", "High", "Safe callback or controlled fetch behavior confirms server-side URL fetch.", _standard_manual("External URL fetch needs permission."), ("URL parameter exists.",), ("Detect URL-fetch parameters.",), ("Metadata service testing.",), ("Use approved callback and never metadata IPs unless explicitly allowed."), "SSRF can let an attacker make server-side network requests."),
        _bug("external_url_fetch", "External URL fetch behavior", "SSRF", "Medium", "Server fetches an external benign URL in a controlled way.", _standard_manual("Needs OOB or response proof."), ("Client-side redirect.",), ("Identify fetch-like parameters.",), ("Internal network probing.",), ("Confirm benign external fetch if permitted."), "External fetch behavior can become SSRF if controls are weak."),
        _bug("webhook_callback_risk", "Webhook/callback URL risk", "SSRF", "Medium", "Webhook accepts arbitrary callback URL with risk context.", _standard_manual("Needs safe callback proof."), ("Webhook docs only.",), ("Detect callback fields.",), ("Internal callbacks.",), ("Use owned callback endpoint only if allowed."), "Callback handling can be abused for SSRF or data exfiltration."),
        _bug("missing_rate_limit_headers", "Missing rate-limit headers", "Rate Limit", "Info", "Header absence is paired with endpoint sensitivity and manual validation plan.", _standard_manual("Missing headers alone are not a Great Finding."), ("Headers hidden by gateway.",), ("Observe headers on low-rate requests.",), ("High-volume testing.",), ("Check program rules before manual testing."), "Missing rate-limit signals may indicate weak abuse controls."),
        _bug("rate_limit_weakness_candidate", "Rate-limit weakness candidate", "Rate Limit", "Medium", "Low-volume evidence suggests lack of throttling on sensitive action.", _standard_manual("Requires program permission for volume testing."), ("No header on static page.",), ("Low-rate observation only.",), ("DoS or brute-force volume.",), ("Manual low-volume validation within program rules."), "Weak rate limits can allow abuse of sensitive workflows."),
        _bug("login_rate_limit_concern", "Login rate-limit concern", "Rate Limit", "Medium", "Login flow lacks visible throttling signals; no high-volume test performed.", _standard_manual("Requires rate-limit testing permission."), ("Normal 401 responses.",), ("Inspect headers and lockout hints.",), ("Credential stuffing or brute force.",), ("Check program rules before manual testing."), "Weak login throttling can enable password attacks."),
        _bug("otp_rate_limit_concern", "OTP rate-limit concern", "Rate Limit", "High", "OTP endpoint appears unthrottled from safe signals.", _standard_manual("OTP volume testing requires permission."), ("OTP form exists.",), ("Observe headers and response hints.",), ("OTP brute force.",), ("Use owned account and approved low-volume test."), "Weak OTP throttling can enable account takeover."),
        _bug("password_reset_rate_limit_concern", "Password reset rate-limit concern", "Rate Limit", "Medium", "Password reset flow lacks visible throttling signals.", _standard_manual("Requires permission for repeated requests."), ("Reset form exists.",), ("Observe headers and response hints.",), ("Flooding emails.",), ("Check rules before manual validation."), "Weak reset rate limits can enable abuse or enumeration."),
        _bug("missing_hsts_context", "Missing HSTS with context", "Headers/Cookies", "Low", "Missing HSTS is tied to HTTPS downgrade risk for sensitive app.", _standard_manual("Missing header alone is low/noise."), ("Non-sensitive or HTTP-only site.",), ("Inspect response headers.",), ("Network MITM testing.",), ("Confirm sensitive HTTPS context."), "Missing HSTS can allow downgrade attacks in some contexts."),
        _bug("missing_csp_context", "Missing CSP with exploitability context", "Headers/Cookies", "Low", "Missing CSP is tied to a confirmed injection surface.", _standard_manual("Missing CSP alone is not bounty-worthy."), ("Header missing on static page.",), ("Inspect headers.",), ("Attempting XSS exploitation.",), ("Pair with exploitable injection context."), "CSP can reduce browser injection impact."),
        _bug("missing_xfo_clickjacking", "Missing X-Frame-Options with clickjacking context", "Headers/Cookies", "Low", "Sensitive state-changing page is frameable.", _standard_manual("Needs clickjacking impact context."), ("Marketing page frameable.",), ("Inspect frame headers.",), ("Performing user actions.",), ("Confirm sensitive page and UI action."), "Clickjacking can trick users into actions."),
        _bug("insecure_cookie_flags_impact", "Insecure cookie flags with real impact", "Headers/Cookies", "Medium", "Session cookie lacks flags and impact is clear.", _standard_manual("Need cookie purpose confirmation."), ("Analytics cookie missing flags.",), ("Inspect Set-Cookie.",), ("Session theft simulation.",), ("Confirm cookie is session/security-sensitive."), "Missing cookie flags can expose sessions in realistic attacks."),
        _bug("permissive_cors_credentials", "Permissive CORS with credential risk", "Headers/Cookies", "High", "Credentialed permissive CORS is confirmed on sensitive endpoint.", _standard_manual("Needs credentialed impact proof."), ("Wildcard without credentials.",), ("Inspect CORS headers.",), ("Reading real user data.",), ("Use owned account and safe origin."), "Credentialed permissive CORS can leak authenticated data."),
        _bug("sensitive_data_headers", "Sensitive data in headers", "Information Disclosure", "Medium", "Sensitive token or personal data appears in response headers.", _standard_manual("Need redacted sensitive evidence."), ("Opaque request IDs.",), ("Inspect headers and redact secrets.",), ("Using leaked secrets.",), ("Confirm data is sensitive and redact it."), "Sensitive headers can leak credentials or personal data."),
        _bug("exposed_secret_candidate", "Exposed secrets candidate", "Information Disclosure", "High", "High-confidence secret pattern is validated as live or sensitive without printing it.", _standard_manual("Needs validation and redaction."), ("Test keys or example tokens.",), ("Detect and redact secret patterns.",), ("Using secrets.",), ("Validate safely and rotate if real."), "Exposed secrets can grant unauthorized access."),
        _bug("exposed_backup_config", "Exposed backup/config file", "Information Disclosure", "High", "Backup/config file is reachable and contains sensitive config.", _standard_manual("Need content sensitivity proof."), ("Empty backup file.",), ("Check common benign filenames at low rate.",), ("Downloading large sensitive files.",), ("Confirm with minimal redacted snippet."), "Exposed config can leak credentials and internals."),
        _bug("exposed_env_candidate", "Exposed .env candidate", "Information Disclosure", "Critical", ".env content is reachable and contains secrets or sensitive config.", _standard_manual("Need redacted proof only."), ("Fake .env sample.",), ("Single safe request for .env if in scope.",), ("Using leaked credentials.",), ("Report redacted keys and request rotation."), ".env exposure can disclose production secrets."),
        _bug("exposed_source_map", "Exposed source map", "Information Disclosure", "Low", "Source map reveals sensitive source, endpoints, or secrets.", _standard_manual("Source map alone is usually informational."), ("Public client source by design.",), ("Detect source map links.",), ("Mining secrets aggressively.",), ("Review for sensitive content only."), "Source maps can expose hidden endpoints or secrets."),
        _bug("exposed_debug_endpoint", "Exposed debug endpoint", "Information Disclosure", "High", "Debug endpoint exposes sensitive state or controls.", _standard_manual("Need sensitivity proof."), ("Health endpoint.",), ("Detect debug route responses.",), ("Invoking debug actions.",), ("Confirm exposed data/control sensitivity."), "Debug endpoints can reveal internals or enable abuse."),
        _bug("verbose_error_sensitive", "Verbose error with sensitive info", "Information Disclosure", "Medium", "Error includes secret, stack, path, or sensitive business data.", _standard_manual("Need redacted sensitive snippet."), ("Generic error message.",), ("Observe safe errors.",), ("Forcing destructive errors.",), ("Confirm sensitivity and redact."), "Verbose errors can leak useful attack details."),
        _bug("directory_listing", "Directory listing", "Information Disclosure", "Medium", "Directory listing exposes sensitive files.", _standard_manual("Need sensitive file proof."), ("Listing of public assets.",), ("Observe directory index.",), ("Downloading sensitive files.",), ("Confirm listed files are sensitive."), "Directory listing can expose source, backups, or secrets."),
        _bug("public_admin_auth_present", "Public admin panel with auth present", "Technology/Surface", "Info", "Admin panel is public but protected by auth.", _standard_manual("Usually informational unless auth weakness exists."), ("Normal admin login.",), ("Detect admin login pages.",), ("Brute forcing admin.",), ("Use as context for auth testing."), "Public admin panels increase attack surface."),
        _bug("public_admin_no_auth", "Public admin panel without auth", "Access Control", "Critical", "Admin function is reachable without authentication.", _standard_manual("Need no-auth function proof."), ("Admin login page only.",), ("Check status and page type.",), ("Changing admin state.",), ("Confirm sensitive admin function exposure."), "Unauthenticated admin access can compromise the application."),
        _bug("price_manipulation_candidate", "Price manipulation candidate", "Business Logic", "High", "Owned checkout/order flow accepts manipulated price.", _standard_manual("Requires payment/order workflow permission."), ("Price field in client JS.",), ("Identify price parameters.",), ("Completing real purchases.",), ("Use sandbox/test order if allowed."), "Price manipulation can cause financial loss."),
        _bug("coupon_abuse_candidate", "Coupon abuse candidate", "Business Logic", "Medium", "Coupon workflow allows unauthorized stacking/reuse in controlled test.", _standard_manual("Requires business rules understanding."), ("Coupon field exists.",), ("Map coupon flow.",), ("Abusing real promotions.",), ("Use test coupon/order if allowed."), "Coupon abuse can reduce revenue or bypass limits."),
        _bug("order_ownership_candidate", "Order ownership issue candidate", "Business Logic", "High", "Controlled user accesses another controlled user's order.", _standard_manual("Needs two authorized accounts."), ("Order ID pattern only.",), ("Detect order routes and IDs.",), ("Accessing real orders.",), ("Compare with two test accounts."), "Order ownership flaws can expose customer data."),
        _bug("workflow_bypass_candidate", "Workflow bypass candidate", "Business Logic", "High", "Controlled flow skips required approval/payment/step.", _standard_manual("Needs workflow understanding."), ("Hidden route discovered.",), ("Map workflow states.",), ("Bypassing real payment or approval.",), ("Use sandbox flow and document skipped step."), "Workflow bypass can grant unpaid or unauthorized benefits."),
        _bug("negative_quantity_candidate", "Negative quantity candidate", "Business Logic", "Medium", "Owned test cart/order accepts negative quantity with impact.", _standard_manual("Requires safe cart/order test."), ("Quantity field exists.",), ("Identify numeric fields.",), ("Submitting real orders.",), ("Use test cart/order if allowed."), "Negative quantities can alter totals or inventory."),
        _bug("payment_state_mismatch", "Payment state mismatch candidate", "Business Logic", "High", "Order state can be marked paid/fulfilled without valid payment in sandbox.", _standard_manual("Requires payment workflow permission."), ("Payment status field visible.",), ("Map payment callbacks.",), ("Manipulating real payments.",), ("Use sandbox payment environment only."), "Payment state flaws can enable unpaid fulfillment."),
        _bug("interesting_js_endpoint", "Interesting JS endpoint", "Technology/Surface", "Info", "JavaScript reveals endpoint worth manual review.", _standard_manual("Surface discovery alone is informational."), ("Unused route strings.",), ("Extract endpoints from JS.",), ("Calling sensitive endpoints blindly.",), ("Review endpoint with auth context."), "JS endpoints help target authorized testing."),
        _bug("hidden_api_route", "Hidden API route", "Technology/Surface", "Info", "Hidden route discovered from passive sources.", _standard_manual("Needs impact proof."), ("Dead code route.",), ("Catalog route from JS/crawler.",), ("Active probing outside scope.",), ("Confirm in-scope behavior safely."), "Hidden API routes may expose untested functionality."),
        _bug("upload_surface", "Upload surface", "Technology/Surface", "Info", "Upload form or endpoint found.", _standard_manual("Needs upload permission and proof."), ("Static form only.",), ("Detect upload surfaces.",), ("Uploading files without permission.",), ("Check program rules before testing uploads."), "Upload surfaces can lead to file handling vulnerabilities."),
        _bug("login_surface", "Login surface", "Technology/Surface", "Info", "Login endpoint found.", _standard_manual("Needs auth/rate-limit proof."), ("Normal login page.",), ("Detect login URLs.",), ("Credential attacks.",), ("Use only owned credentials."), "Login surfaces guide auth and rate-limit testing."),
        _bug("admin_surface", "Admin surface", "Technology/Surface", "Info", "Admin surface found.", _standard_manual("Needs access-control proof."), ("Protected admin login.",), ("Detect admin routes.",), ("Brute force or bypass attempts.",), ("Confirm auth expectations safely."), "Admin surfaces guide access-control review."),
        _bug("graphql_surface", "GraphQL surface", "Technology/Surface", "Info", "GraphQL surface found.", _standard_manual("Needs schema/auth proof."), ("GraphQL route exists.",), ("Detect GraphQL endpoint.",), ("Introspection if disallowed.",), ("Check program rules before schema review."), "GraphQL surfaces guide API authorization testing."),
    )
}


ALIASES = {
    "id or": "idor",
    "idor candidate": "idor",
    "bola candidate": "bola",
    "broken object level authorization": "bola",
    "open redirect": "open_redirect_confirmed",
    "open redirect candidate": "open_redirect_candidate",
    "missing security headers": "missing_csp_context",
    "rate limiting": "rate_limit_weakness_candidate",
    "file upload endpoint candidate": "upload_surface",
    "graphql endpoint candidate": "graphql_surface",
    "graphql introspection enabled": "graphql_introspection_allowed",
    "ssrf": "ssrf_candidate",
    "ssrf candidate": "ssrf_candidate",
    "sql injection": "sql_injection_candidate",
    "xss": "reflected_xss_candidate",
    "cors": "unsafe_cors_impact",
}


def all_bug_types() -> list[BugType]:
    return sorted(BUG_TYPES.values(), key=lambda item: (item.category, item.name))


def bug_type_for(finding: dict) -> BugType | None:
    raw = " ".join(
        str(finding.get(key, ""))
        for key in ("bug_type_id", "vuln_type", "vulnerability_class", "title")
    ).lower()
    compact = raw.replace("-", " ").replace("_", " ")
    for bug_id, item in BUG_TYPES.items():
        if bug_id in raw or item.name.lower() in compact:
            return item
    for alias, bug_id in ALIASES.items():
        if alias in compact:
            return BUG_TYPES.get(bug_id)
    return None


def registry_as_dict() -> list[dict]:
    return [item.to_dict() for item in all_bug_types()]
