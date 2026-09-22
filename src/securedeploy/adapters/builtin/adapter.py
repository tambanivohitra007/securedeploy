"""Built-in HTTP security checks.

No external tools required. Performs:
- HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.)
- HTTPS enforcement (HTTP → HTTPS redirect)
- TLS certificate validity (expiry, hostname match)
- Cookie security flags
- Basic CORS misconfiguration

Produces NormalizedFindings directly rather than going through a separate
normalizer, because this adapter IS the scanner and the normalizer.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from securedeploy.adapters.base import (
    AdapterOptions,
    AvailabilityResult,
    RawResult,
    ScannerAdapter,
    ToolError,
)
from securedeploy.config.models import Profile, ProjectConfig
from securedeploy.core.cancel import CancelToken
from securedeploy.findings.fingerprint import stamp_finding
from securedeploy.findings.models import (
    Confidence,
    Evidence,
    FindingLocation,
    LocationType,
    NormalizedFinding,
    Severity,
    SourceInfo,
)

log = logging.getLogger(__name__)

VERSION = "0.1.0"


class BuiltinAdapter(ScannerAdapter):
    tool_id = "builtin"
    display_name = "Built-in HTTP Checks"

    # Always available — no external dependency
    async def check_available(self) -> AvailabilityResult:
        return AvailabilityResult(available=True, version=VERSION, mode="native")

    async def run(
        self,
        config: ProjectConfig,
        profile: Profile,
        options: AdapterOptions,
        cancel_token: CancelToken,
    ) -> RawResult:
        start = time.monotonic()
        findings: list[dict] = []

        target_url = config.target.url
        scope = config.target.scope

        try:
            async with httpx.AsyncClient(
                timeout=15.0,
                follow_redirects=False,
                verify=False,  # we check TLS separately
            ) as client:
                if cancel_token.is_cancelled:
                    return RawResult(tool=self.tool_id, raw_output="[]", duration_seconds=0)

                # 1. HTTPS enforcement check
                if config.testing.tls:
                    https_findings = await self._check_https_enforcement(client, target_url)
                    findings.extend(https_findings)

                if cancel_token.is_cancelled:
                    return RawResult(tool=self.tool_id, raw_output=json.dumps(findings))

                # 2. TLS certificate validity
                if config.testing.tls:
                    tls_findings = await self._check_tls_cert(target_url)
                    findings.extend(tls_findings)

                if cancel_token.is_cancelled:
                    return RawResult(tool=self.tool_id, raw_output=json.dumps(findings))

                # 3. Security headers
                if config.testing.headers:
                    header_findings = await self._check_security_headers(
                        client, target_url
                    )
                    findings.extend(header_findings)

                if cancel_token.is_cancelled:
                    return RawResult(tool=self.tool_id, raw_output=json.dumps(findings))

                # 4. Cookie security
                header_findings_http = await self._check_cookie_security(
                    client, target_url
                )
                findings.extend(header_findings_http)

                # 5. CORS misconfiguration
                cors_findings = await self._check_cors(client, target_url)
                findings.extend(cors_findings)

        except asyncio.TimeoutError:
            return RawResult(
                tool=self.tool_id,
                error=ToolError(
                    tool=self.tool_id,
                    reason=ToolError.TIMEOUT,
                    message=f"Built-in checks timed out",
                    duration_seconds=time.monotonic() - start,
                ),
            )
        except Exception as e:
            log.debug("Built-in adapter error: %s", e)
            return RawResult(
                tool=self.tool_id,
                raw_output=json.dumps(findings),
                exit_code=0,
                stderr=str(e),
                duration_seconds=time.monotonic() - start,
                tool_version=VERSION,
            )

        return RawResult(
            tool=self.tool_id,
            raw_output=json.dumps(findings),
            exit_code=0,
            duration_seconds=time.monotonic() - start,
            tool_version=VERSION,
        )

    def normalize(self, raw: RawResult) -> list[NormalizedFinding]:
        if raw.error or not raw.raw_output:
            return []
        try:
            findings_data = json.loads(raw.raw_output)
        except (json.JSONDecodeError, Exception):
            return []
        # Built-in findings are already NormalizedFinding-compatible dicts
        findings = []
        for d in findings_data:
            try:
                f = NormalizedFinding.model_validate(d)
                stamp_finding(f)
                findings.append(f)
            except Exception as e:
                log.debug("Failed to deserialize builtin finding: %s", e)
        return findings

    # ── Private check methods ────────────────────────────────────────────

    async def _check_https_enforcement(
        self, client: httpx.AsyncClient, url: str
    ) -> list[dict]:
        findings = []
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return findings  # Only check if target is HTTPS

        # Try the HTTP variant
        http_url = url.replace("https://", "http://", 1)
        try:
            resp = await client.get(http_url)
            if resp.status_code not in (301, 302, 307, 308):
                findings.append(
                    self._make_finding(
                        rule_id="https-not-enforced",
                        title="HTTP not redirected to HTTPS",
                        description=(
                            f"The application at {http_url} does not redirect HTTP requests "
                            "to HTTPS. Users connecting over plain HTTP will not be automatically "
                            "upgraded to a secure connection."
                        ),
                        severity=Severity.MEDIUM,
                        url=http_url,
                        endpoint=parsed.path or "/",
                        location_type=LocationType.TLS,
                        evidence=Evidence(
                            response_status=resp.status_code,
                            description=f"HTTP request returned {resp.status_code}, expected 3xx redirect",
                        ),
                        remediation="Configure your web server to issue a permanent (301) redirect from HTTP to HTTPS.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                        cwe=["CWE-319"],
                    )
                )
            else:
                location = resp.headers.get("location", "")
                if not location.startswith("https://"):
                    findings.append(
                        self._make_finding(
                            rule_id="https-redirect-wrong-scheme",
                            title="HTTP redirect does not point to HTTPS",
                            description=f"HTTP redirect Location header is '{location}', not an HTTPS URL.",
                            severity=Severity.MEDIUM,
                            url=http_url,
                            endpoint=parsed.path or "/",
                            location_type=LocationType.TLS,
                            evidence=Evidence(
                                response_status=resp.status_code,
                                description=f"Location: {location}",
                            ),
                            remediation="Ensure the redirect Location header points to an https:// URL.",
                            cwe=["CWE-319"],
                        )
                    )
        except Exception:
            pass  # Connection refused is fine — HTTP may not be listening

        return findings

    async def _check_tls_cert(self, url: str) -> list[dict]:
        findings = []
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return findings
        host = parsed.hostname or ""
        port = parsed.port or 443

        try:
            ctx = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=10.0,
            )
            # Get certificate info
            cert = writer.get_extra_info("ssl_object")
            if cert:
                ssl_obj = cert
                cert_info = ssl_obj.getpeercert()
                if cert_info:
                    not_after = cert_info.get("notAfter", "")
                    if not_after:
                        try:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            expiry = expiry.replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            days_left = (expiry - now).days
                            if days_left < 0:
                                findings.append(self._make_finding(
                                    rule_id="tls-cert-expired",
                                    title="TLS certificate has expired",
                                    description=f"The TLS certificate for {host} expired on {not_after}.",
                                    severity=Severity.CRITICAL,
                                    url=url,
                                    endpoint="/",
                                    location_type=LocationType.TLS,
                                    evidence=Evidence(description=f"Certificate expired: {not_after}"),
                                    remediation="Renew the TLS certificate immediately.",
                                    cwe=["CWE-298"],
                                ))
                            elif days_left < 30:
                                findings.append(self._make_finding(
                                    rule_id="tls-cert-expiring-soon",
                                    title=f"TLS certificate expires in {days_left} days",
                                    description=f"The TLS certificate for {host} expires on {not_after}.",
                                    severity=Severity.MEDIUM,
                                    url=url,
                                    endpoint="/",
                                    location_type=LocationType.TLS,
                                    evidence=Evidence(description=f"Certificate expires: {not_after}"),
                                    remediation="Renew the TLS certificate before it expires.",
                                    cwe=["CWE-298"],
                                ))
                        except ValueError:
                            pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except ssl.SSLCertVerificationError as e:
            findings.append(self._make_finding(
                rule_id="tls-cert-invalid",
                title="TLS certificate validation failed",
                description=f"TLS certificate for {host} failed validation: {e}",
                severity=Severity.HIGH,
                url=url,
                endpoint="/",
                location_type=LocationType.TLS,
                evidence=Evidence(description=str(e)),
                remediation="Ensure the server uses a valid certificate signed by a trusted CA.",
                cwe=["CWE-295"],
            ))
        except Exception as e:
            log.debug("TLS check failed for %s: %s", url, e)

        return findings

    async def _check_security_headers(
        self, client: httpx.AsyncClient, url: str
    ) -> list[dict]:
        findings = []
        try:
            resp = await client.get(url)
        except Exception:
            return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # HSTS
        if urlparse(url).scheme == "https" and "strict-transport-security" not in headers:
            findings.append(self._make_finding(
                rule_id="missing-hsts",
                title="Missing HTTP Strict-Transport-Security header",
                description="HSTS is not set. Browsers will not enforce HTTPS connections for this origin.",
                severity=Severity.MEDIUM,
                url=url, endpoint=urlparse(url).path or "/",
                location_type=LocationType.WEB,
                evidence=Evidence(description="Header Strict-Transport-Security not present"),
                remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                references=["https://owasp.org/www-project-secure-headers/"],
                cwe=["CWE-319"],
            ))
        else:
            hsts_val = headers.get("strict-transport-security", "")
            if "max-age=" in hsts_val:
                try:
                    max_age = int(hsts_val.split("max-age=")[1].split(";")[0].strip())
                    if max_age < 31536000:
                        findings.append(self._make_finding(
                            rule_id="hsts-max-age-too-short",
                            title="HSTS max-age is less than 1 year",
                            description=f"HSTS max-age is {max_age} seconds (< 31536000).",
                            severity=Severity.LOW,
                            url=url, endpoint="/",
                            location_type=LocationType.WEB,
                            evidence=Evidence(description=f"Strict-Transport-Security: {hsts_val}"),
                            remediation="Set max-age to at least 31536000 (1 year).",
                            cwe=["CWE-319"],
                        ))
                except (ValueError, IndexError):
                    pass

        # X-Content-Type-Options
        if "x-content-type-options" not in headers:
            findings.append(self._make_finding(
                rule_id="missing-x-content-type-options",
                title="Missing X-Content-Type-Options header",
                description="X-Content-Type-Options: nosniff is not set, enabling MIME-type sniffing attacks.",
                severity=Severity.LOW,
                url=url, endpoint="/",
                location_type=LocationType.WEB,
                evidence=Evidence(description="Header X-Content-Type-Options not present"),
                remediation="Add: X-Content-Type-Options: nosniff",
                cwe=["CWE-16"],
            ))

        # X-Frame-Options / CSP frame-ancestors
        has_frame_protection = (
            "x-frame-options" in headers
            or ("content-security-policy" in headers and "frame-ancestors" in headers.get("content-security-policy", ""))
        )
        if not has_frame_protection:
            findings.append(self._make_finding(
                rule_id="missing-x-frame-options",
                title="Missing X-Frame-Options or CSP frame-ancestors",
                description="The application does not set X-Frame-Options or CSP frame-ancestors, enabling clickjacking.",
                severity=Severity.MEDIUM,
                url=url, endpoint="/",
                location_type=LocationType.WEB,
                evidence=Evidence(description="No frame protection header found"),
                remediation="Add X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'",
                references=["https://owasp.org/www-community/attacks/Clickjacking"],
                cwe=["CWE-1021"],
            ))

        # Content-Security-Policy
        if "content-security-policy" not in headers:
            findings.append(self._make_finding(
                rule_id="missing-csp",
                title="Missing Content-Security-Policy header",
                description="No Content-Security-Policy header is present. This increases XSS risk.",
                severity=Severity.MEDIUM,
                url=url, endpoint="/",
                location_type=LocationType.WEB,
                evidence=Evidence(description="Header Content-Security-Policy not present"),
                remediation="Implement a Content-Security-Policy. Start with a report-only policy.",
                references=["https://content-security-policy.com/"],
                cwe=["CWE-79"],
            ))
        else:
            csp = headers.get("content-security-policy", "")
            if "unsafe-inline" in csp:
                findings.append(self._make_finding(
                    rule_id="csp-unsafe-inline",
                    title="Content-Security-Policy allows unsafe-inline",
                    description="CSP contains 'unsafe-inline', significantly weakening XSS protection.",
                    severity=Severity.MEDIUM,
                    url=url, endpoint="/",
                    location_type=LocationType.WEB,
                    evidence=Evidence(description=f"Content-Security-Policy: {csp[:200]}"),
                    remediation="Remove 'unsafe-inline' from CSP. Use nonces or hashes for inline scripts.",
                    cwe=["CWE-79"],
                ))

        # Referrer-Policy
        if "referrer-policy" not in headers:
            findings.append(self._make_finding(
                rule_id="missing-referrer-policy",
                title="Missing Referrer-Policy header",
                description="No Referrer-Policy is set. Sensitive URL parameters may leak to third parties.",
                severity=Severity.LOW,
                url=url, endpoint="/",
                location_type=LocationType.WEB,
                evidence=Evidence(description="Header Referrer-Policy not present"),
                remediation="Add: Referrer-Policy: strict-origin-when-cross-origin",
                cwe=["CWE-200"],
            ))

        # Permissions-Policy (formerly Feature-Policy)
        if "permissions-policy" not in headers and "feature-policy" not in headers:
            findings.append(self._make_finding(
                rule_id="missing-permissions-policy",
                title="Missing Permissions-Policy header",
                description="No Permissions-Policy header restricts access to browser features.",
                severity=Severity.INFORMATIONAL,
                url=url, endpoint="/",
                location_type=LocationType.WEB,
                evidence=Evidence(description="Header Permissions-Policy not present"),
                remediation="Add a Permissions-Policy header to restrict browser features (camera, microphone, etc.)",
                cwe=["CWE-16"],
            ))

        # Server header disclosure
        if "server" in headers:
            server_val = headers["server"]
            # Flag if version is disclosed (has digits)
            if any(c.isdigit() for c in server_val):
                findings.append(self._make_finding(
                    rule_id="server-version-disclosed",
                    title="Server header discloses version information",
                    description=f"Server header value '{server_val}' discloses server software and version.",
                    severity=Severity.LOW,
                    url=url, endpoint="/",
                    location_type=LocationType.WEB,
                    evidence=Evidence(description=f"Server: {server_val}"),
                    remediation="Configure the web server to suppress or generalize the Server header.",
                    cwe=["CWE-200"],
                ))

        # X-Powered-By
        if "x-powered-by" in headers:
            findings.append(self._make_finding(
                rule_id="x-powered-by-disclosed",
                title="X-Powered-By header discloses technology stack",
                description=f"X-Powered-By: {headers['x-powered-by']} reveals implementation details.",
                severity=Severity.LOW,
                url=url, endpoint="/",
                location_type=LocationType.WEB,
                evidence=Evidence(description=f"X-Powered-By: {headers['x-powered-by']}"),
                remediation="Remove or suppress the X-Powered-By header.",
                cwe=["CWE-200"],
            ))

        return findings

    async def _check_cookie_security(
        self, client: httpx.AsyncClient, url: str
    ) -> list[dict]:
        findings = []
        try:
            resp = await client.get(url)
        except Exception:
            return findings

        for cookie in resp.cookies.jar:
            name = cookie.name
            is_https = urlparse(url).scheme == "https"

            if is_https and not cookie.secure:
                findings.append(self._make_finding(
                    rule_id="cookie-missing-secure",
                    title=f"Cookie '{name}' missing Secure flag",
                    description=f"Cookie '{name}' is served over HTTPS but does not have the Secure flag. "
                                "It may be transmitted over HTTP.",
                    severity=Severity.MEDIUM,
                    url=url, endpoint="/",
                    location_type=LocationType.WEB,
                    evidence=Evidence(description=f"Set-Cookie: {name}=... (no Secure flag)"),
                    remediation=f"Add the Secure flag to cookie '{name}'.",
                    cwe=["CWE-614"],
                ))

            if not cookie.has_nonstandard_attr("HttpOnly") and not getattr(cookie, "_rest", {}).get("HttpOnly"):
                # httpx/requests may not expose HttpOnly directly — check raw headers
                pass  # More reliable check via raw header parsing below

        # Check raw Set-Cookie headers for HttpOnly and SameSite
        raw_set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not raw_set_cookies:
            raw_set_cookies = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]

        for raw_cookie in raw_set_cookies:
            parts = [p.strip().lower() for p in raw_cookie.split(";")]
            name_val = raw_cookie.split(";")[0].split("=")[0].strip()

            if "httponly" not in parts:
                findings.append(self._make_finding(
                    rule_id="cookie-missing-httponly",
                    title=f"Cookie '{name_val}' missing HttpOnly flag",
                    description=f"Cookie '{name_val}' does not have the HttpOnly flag. "
                                "It can be accessed by JavaScript, increasing XSS impact.",
                    severity=Severity.MEDIUM,
                    url=url, endpoint="/",
                    location_type=LocationType.WEB,
                    evidence=Evidence(description=f"Set-Cookie: {raw_cookie[:100]}"),
                    remediation=f"Add the HttpOnly flag to cookie '{name_val}'.",
                    cwe=["CWE-1004"],
                ))

            samesite_values = [p for p in parts if p.startswith("samesite=")]
            if not samesite_values:
                findings.append(self._make_finding(
                    rule_id="cookie-missing-samesite",
                    title=f"Cookie '{name_val}' missing SameSite attribute",
                    description=f"Cookie '{name_val}' does not have a SameSite attribute, increasing CSRF risk.",
                    severity=Severity.LOW,
                    url=url, endpoint="/",
                    location_type=LocationType.WEB,
                    evidence=Evidence(description=f"Set-Cookie: {raw_cookie[:100]}"),
                    remediation=f"Add SameSite=Strict or SameSite=Lax to cookie '{name_val}'.",
                    cwe=["CWE-352"],
                ))
            elif "samesite=none" in parts and "secure" not in parts:
                findings.append(self._make_finding(
                    rule_id="cookie-samesite-none-without-secure",
                    title=f"Cookie '{name_val}' uses SameSite=None without Secure",
                    description="SameSite=None requires the Secure flag, otherwise the cookie is rejected by modern browsers.",
                    severity=Severity.MEDIUM,
                    url=url, endpoint="/",
                    location_type=LocationType.WEB,
                    evidence=Evidence(description=f"Set-Cookie: {raw_cookie[:100]}"),
                    remediation="Add the Secure flag when using SameSite=None.",
                    cwe=["CWE-614"],
                ))

        return findings

    async def _check_cors(
        self, client: httpx.AsyncClient, url: str
    ) -> list[dict]:
        findings = []
        try:
            # Send a cross-origin request with a crafted Origin header
            evil_origin = "https://attacker-controlled.example.com"
            resp = await client.get(url, headers={"Origin": evil_origin})
            headers = {k.lower(): v for k, v in resp.headers.items()}

            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "")

            if acao == "*" and acac.lower() == "true":
                findings.append(self._make_finding(
                    rule_id="cors-wildcard-with-credentials",
                    title="CORS wildcard (*) combined with Allow-Credentials: true",
                    description=(
                        "Access-Control-Allow-Origin: * combined with "
                        "Access-Control-Allow-Credentials: true is invalid per spec and "
                        "may be misimplemented in some frameworks, allowing credential theft."
                    ),
                    severity=Severity.HIGH,
                    url=url, endpoint="/",
                    location_type=LocationType.WEB,
                    evidence=Evidence(
                        description=f"ACAO: {acao}, ACAC: {acac}",
                    ),
                    remediation="Never use Access-Control-Allow-Origin: * with Allow-Credentials: true. "
                                "Explicitly whitelist trusted origins.",
                    references=["https://portswigger.net/web-security/cors"],
                    cwe=["CWE-942"],
                    owasp_top10=["A05:2021-Security Misconfiguration"],
                ))

            elif acao == evil_origin:
                if acac.lower() == "true":
                    findings.append(self._make_finding(
                        rule_id="cors-reflects-origin-with-credentials",
                        title="CORS reflects arbitrary Origin with Allow-Credentials",
                        description=(
                            "The server reflects the request's Origin header back in "
                            "Access-Control-Allow-Origin and also sets Allow-Credentials: true. "
                            "This allows any website to make credentialed cross-origin requests."
                        ),
                        severity=Severity.HIGH,
                        url=url, endpoint="/",
                        location_type=LocationType.WEB,
                        evidence=Evidence(
                            request=f"Origin: {evil_origin}",
                            description=f"ACAO: {acao}, ACAC: {acac}",
                        ),
                        remediation="Validate the Origin header against an explicit whitelist before reflecting it.",
                        references=["https://portswigger.net/web-security/cors"],
                        cwe=["CWE-942"],
                        owasp_top10=["A05:2021-Security Misconfiguration"],
                    ))
        except Exception:
            pass

        return findings

    def _make_finding(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        url: str,
        endpoint: str,
        location_type: LocationType,
        evidence: Evidence,
        remediation: str = "",
        references: list[str] | None = None,
        cwe: list[str] | None = None,
        owasp_top10: list[str] | None = None,
        method: str = "GET",
    ) -> dict:
        finding = NormalizedFinding(
            title=title,
            description=description,
            severity=severity,
            confidence=Confidence.HIGH,
            category=self._category_for(location_type, cwe or []),
            owasp_top10=owasp_top10 or [],
            cwe=cwe or [],
            source=SourceInfo(
                tool="builtin",
                tool_version=VERSION,
                rule_id=rule_id,
                suite="HTTP Security Checks",
            ),
            location=FindingLocation(
                type=location_type,
                url=url,
                endpoint=endpoint,
                method=method,
            ),
            evidence=evidence,
            remediation=remediation,
            references=references or [],
        )
        return finding.model_dump(mode="json")

    def _category_for(self, loc_type: LocationType, cwes: list[str]) -> str:
        if loc_type == LocationType.TLS:
            return "TLS/SSL Configuration"
        cwe_set = set(cwes)
        if "CWE-614" in cwe_set or "CWE-1004" in cwe_set or "CWE-352" in cwe_set:
            return "Insecure Cookie"
        if "CWE-942" in cwe_set:
            return "CORS Misconfiguration"
        return "HTTP Security Headers"
