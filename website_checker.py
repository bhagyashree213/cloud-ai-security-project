"""
CloudSentinel — Website Threat Checker & Defensive Security Analysis Engine.
Provides safe, read-only educational inspection of public web domains:
  1. Strict SSRF, DNS-rebinding, and IP-range validation (blocks localhost, private, link-local, cloud-metadata 169.254.169.254)
  2. Safe HTTPS reachability and TLS/SSL certificate lifecycle inspection (expiration, issuer, cipher)
  3. HTTP Security Headers analysis (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, etc.)
  4. Optional VirusTotal API reputation check (gracefully disabled when unconfigured, no invented data)
  5. Overall assessment synthesis ('No Major Issues Found', 'Potential Risk', 'Unable to Determine')

Ethical & Defensive Boundaries:
  - Strictly read-only; never executes exploits, port scans, or intrusive attacks.
  - Does not classify a site as safe merely because HTTPS is active.
  - Does not classify a site as malicious merely because optional headers are missing.
"""

from pathlib import Path
import os
import sys
import socket
import ssl
import ipaddress
import urllib.parse
import base64
from datetime import datetime, timezone
import time
from typing import Dict, Any, List, Tuple, Optional
import requests

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Standard HTTP Security Headers to inspect
SECURITY_HEADERS_DEFINITION = {
    "Strict-Transport-Security": {
        "name": "HTTP Strict Transport Security (HSTS)",
        "importance": "High",
        "description": "Instructs web browsers to exclusively connect over encrypted HTTPS, preventing SSL-stripping attacks."
    },
    "Content-Security-Policy": {
        "name": "Content Security Policy (CSP)",
        "importance": "High",
        "description": "Restricts sources of executable scripts, stylesheets, and assets to mitigate Cross-Site Scripting (XSS) and injection."
    },
    "X-Content-Type-Options": {
        "name": "MIME Type Sniffing Protection",
        "importance": "Medium",
        "description": "Prevents MIME-confusion attacks by enforcing the declared Content-Type header (nosniff)."
    },
    "X-Frame-Options": {
        "name": "Clickjacking Defense",
        "importance": "Medium",
        "description": "Controls whether the website can be framed inside <frame>, <iframe>, or <object>, protecting against UI redressing/clickjacking."
    },
    "Referrer-Policy": {
        "name": "Referrer Privacy Policy",
        "importance": "Low",
        "description": "Governs how much referrer metadata is transmitted to external links to prevent URL token leakage."
    },
    "Permissions-Policy": {
        "name": "Hardware Permissions Policy",
        "importance": "Low",
        "description": "Allows or disables browser device features (camera, microphone, geolocation) for the site."
    }
}

# Cloud metadata IP (AWS, GCP, Azure, OpenStack)
CLOUD_METADATA_IPS = {"169.254.169.254", "fd00:ec2::254"}


def is_safe_public_ip(ip_str: str) -> Tuple[bool, str]:
    """
    Validates that an IP address is a routable public address.
    Blocks SSRF targets: localhost (127.0.0.0/8), private subnets (RFC 1918),
    link-local (169.254.0.0/16), cloud metadata addresses, loopback, and multicast.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, f"Invalid IP address format: '{ip_str}'"

    if ip_str in CLOUD_METADATA_IPS:
        return False, f"Blocked forbidden cloud metadata service address ({ip_str})"

    # Handle NAT64 well-known prefix (RFC 6052 64:ff9b::/96)
    if ip.version == 6:
        nat64_prefix = ipaddress.IPv6Network("64:ff9b::/96")
        if ip in nat64_prefix:
            embedded_ipv4 = ipaddress.IPv4Address(ip.packed[-4:])
            return is_safe_public_ip(str(embedded_ipv4))

    if ip.is_loopback:
        return False, f"Blocked local loopback address ({ip_str})"

    if ip.is_private:
        return False, f"Blocked private RFC 1918 internal network address ({ip_str})"

    if ip.is_link_local:
        return False, f"Blocked link-local autoconfiguration address ({ip_str})"

    if ip.is_multicast:
        return False, f"Blocked multicast address ({ip_str})"

    if ip.is_reserved:
        return False, f"Blocked IETF reserved address ({ip_str})"

    if ip.is_unspecified:
        return False, f"Blocked unspecified wildcard address ({ip_str})"

    return True, "Safe public IP address"


def resolve_hostname_safely(hostname: str) -> Tuple[bool, List[str], str]:
    """
    Performs DNS resolution and verifies that ALL resolved IPs are safe public addresses.
    Prevents DNS-rebinding and SSRF attempts.
    """
    # Reject raw localhost hostnames
    low_host = hostname.lower().strip()
    if low_host in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
        return False, [], "SSRF Defense: 'localhost' resolution is prohibited."

    if low_host.endswith(".local") or low_host.endswith(".internal"):
        return False, [], f"SSRF Defense: Internal network domain '{hostname}' is prohibited."

    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        return False, [], f"DNS Resolution Failed: {str(e)}"

    resolved_ips = list({item[4][0] for item in addr_info})
    if not resolved_ips:
        return False, [], f"No IP addresses resolved for hostname '{hostname}'"

    for ip_str in resolved_ips:
        is_safe, reason = is_safe_public_ip(ip_str)
        if not is_safe:
            return False, resolved_ips, f"SSRF Protection Alert: Hostname '{hostname}' resolved to prohibited address {ip_str} ({reason})."

    return True, resolved_ips, "All resolved addresses verified public."


def sanitize_and_parse_url(raw_input: str) -> Tuple[bool, str, str, int, str]:
    """
    Sanitizes user input URL, enforces http/https protocol, and extracts hostname and port.
    Returns: (is_valid, sanitized_url, hostname, port, error_message)
    """
    clean_input = raw_input.strip()
    if not clean_input:
        return False, "", "", 0, "URL or domain name cannot be empty."

    # Check if a scheme is specified
    if "://" in clean_input:
        scheme_prefix = clean_input.split("://")[0].lower()
        if scheme_prefix not in ("http", "https"):
            return False, "", "", 0, f"Unsupported scheme '{scheme_prefix}'. Only HTTP and HTTPS are permitted."
    else:
        # Prepend https:// if user entered domain without scheme
        clean_input = "https://" + clean_input


    try:
        parsed = urllib.parse.urlparse(clean_input)
    except Exception as e:
        return False, "", "", 0, f"Malformed URL: {str(e)}"

    if parsed.scheme.lower() not in ("http", "https"):
        return False, "", "", 0, f"Unsupported scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "", "", 0, "Could not extract a valid hostname from the provided URL."

    default_port = 443 if parsed.scheme.lower() == "https" else 80
    port = parsed.port or default_port

    # Reconstruct sanitized URL
    sanitized_url = urllib.parse.urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path or "/",
        parsed.params,
        parsed.query,
        ""
    ))

    return True, sanitized_url, hostname.lower(), port, ""


def inspect_tls_certificate(hostname: str, port: int = 443, timeout: float = 4.0) -> Dict[str, Any]:
    """
    Establishes a safe TLS handshake and inspects certificate validity, issuer, and expiration.
    """
    result: Dict[str, Any] = {
        "https_available": False,
        "cert_valid": False,
        "tls_version": None,
        "cipher": None,
        "issuer": "Unknown",
        "subject": "Unknown",
        "valid_from": None,
        "valid_until": None,
        "days_remaining": None,
        "is_expired": False,
        "error": None
    }

    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher_info = ssock.cipher()
                tls_version = ssock.version()

                result["https_available"] = True
                result["cert_valid"] = True
                result["tls_version"] = tls_version
                result["cipher"] = f"{cipher_info[0]} ({cipher_info[1]}-bit)" if cipher_info else "Unknown"

                # Extract Issuer
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Verified CA"

                # Extract Subject
                subject_dict = dict(x[0] for x in cert.get("subject", []))
                result["subject"] = subject_dict.get("commonName") or hostname

                # Dates
                not_before_str = cert.get("notBefore")
                not_after_str = cert.get("notAfter")

                if not_after_str:
                    try:
                        from datetime import timezone
                        exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        result["valid_until"] = exp_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                        now_utc = datetime.now(timezone.utc)
                        days_left = (exp_date - now_utc).days
                        result["days_remaining"] = days_left
                        result["is_expired"] = (days_left < 0)
                    except Exception:
                        result["valid_until"] = not_after_str

                if not_before_str:
                    try:
                        start_date = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
                        result["valid_from"] = start_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                    except Exception:
                        result["valid_from"] = not_before_str

    except ssl.SSLCertVerificationError as e:
        result["https_available"] = True
        result["cert_valid"] = False
        result["error"] = f"SSL Certificate Verification Failed: {e.verify_message}"
        if "expired" in str(e.verify_message).lower() or "not yet valid" in str(e.verify_message).lower():
            result["is_expired"] = True
    except (socket.timeout, TimeoutError):
        result["error"] = f"TLS handshake timed out after {timeout} seconds."
    except Exception as e:
        result["error"] = f"TLS inspection failed: {str(e)}"

    return result


def inspect_http_security_headers(target_url: str, timeout: float = 4.0) -> Dict[str, Any]:
    """
    Dispatches a safe, bounded GET request and audits defensive HTTP headers.
    Enforces redirect validation (re-checking SSRF on every hop) and response-size limits.
    """
    headers_found: Dict[str, Dict[str, Any]] = {}
    missing_headers: List[Dict[str, Any]] = []

    current_url = target_url
    max_redirects = 3
    final_response = None
    response_time_ms = 0.0

    session = requests.Session()
    session.headers.update({"User-Agent": "CloudSentinel-DefensiveCheck/2.0 (Security Scanner)"})

    try:
        for _ in range(max_redirects + 1):
            is_valid, _, host, _, err = sanitize_and_parse_url(current_url)
            if not is_valid:
                return {"success": False, "error": f"Invalid redirect URL: {err}"}

            safe_dns, ips, dns_err = resolve_hostname_safely(host)
            if not safe_dns:
                return {"success": False, "error": dns_err}

            t0 = time.time()
            try:
                resp = session.get(
                    current_url,
                    timeout=timeout,
                    allow_redirects=False,
                    stream=True
                )
            except requests.exceptions.SSLError:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                resp = session.get(
                    current_url,
                    timeout=timeout,
                    allow_redirects=False,
                    stream=True,
                    verify=False
                )
            response_time_ms = round((time.time() - t0) * 1000, 1)

            # Consume max 128KB to prevent memory exhaustion
            for chunk in resp.iter_content(chunk_size=32768):
                break
            resp.close()

            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                redirect_target = resp.headers.get("Location")
                if not redirect_target:
                    final_response = resp
                    break
                current_url = urllib.parse.urljoin(current_url, redirect_target)
            else:
                final_response = resp
                break

        if not final_response:
            return {"success": False, "error": "Exceeded maximum redirect limit (3 hops)."}

        resp_headers = final_response.headers

        # Audit standard headers
        for h_key, meta in SECURITY_HEADERS_DEFINITION.items():
            if h_key in resp_headers:
                headers_found[h_key] = {
                    "name": meta["name"],
                    "importance": meta["importance"],
                    "value": resp_headers[h_key][:120],  # truncate lengthy CSP
                    "description": meta["description"]
                }
            else:
                missing_headers.append({
                    "header": h_key,
                    "name": meta["name"],
                    "importance": meta["importance"],
                    "description": meta["description"]
                })

        return {
            "success": True,
            "status_code": final_response.status_code,
            "latency_ms": response_time_ms,
            "server": resp_headers.get("Server", "Undisclosed / Hidden"),
            "headers_found": headers_found,
            "missing_headers": missing_headers,
            "final_url": current_url,
            "all_headers_count": len(resp_headers)
        }

    except requests.exceptions.Timeout:
        return {"success": False, "error": f"HTTP request timed out after {timeout}s"}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"HTTP request failed: {str(e)}"}


def check_virustotal_reputation(target_url: str, hostname: str) -> Dict[str, Any]:
    """
    Integrates VirusTotal API v3 for URL and domain threat intelligence:
      1. Retrieves API key from Streamlit secrets ('VIRUSTOTAL_API_KEY') or environment variables.
      2. Retrieves existing URL analysis report first via base64url encoded URL identifier.
      3. If URL is not found (404) and a fresh scan is permitted, requests a scan via POST /api/v3/urls
         and retrieves analysis results using the returned analysis ID.
      4. Also checks domain reputation via /api/v3/domains/{domain}.
      5. Respects API rate limits/quotas (4 req/min on public tier) and handles HTTP 429.
      6. Never fabricates results; explicitly notes when API key is missing or data is unavailable.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY")
    if not api_key:
        try:
            import streamlit as st
            if hasattr(st, "secrets"):
                api_key = st.secrets.get("VIRUSTOTAL_API_KEY") or st.secrets.get("VT_API_KEY")
        except Exception:
            pass

    if not api_key:
        return {
            "available": False,
            "status": "NOT_CONFIGURED",
            "source": "VirusTotal v3 API",
            "message": "Reputation lookup is unavailable (VirusTotal API key not configured). Add VIRUSTOTAL_API_KEY in Streamlit secrets (.streamlit/secrets.toml) or environment variables. Reputation lookup skipped without fabricating results.",
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "undetected_count": 0,
            "reputation_score": 0,
            "categories": [],
            "engine_results": {}
        }

    headers = {
        "x-apikey": api_key,
        "User-Agent": "CloudSentinel-DefensiveThreatChecker/2.0"
    }

    malicious_count = 0
    suspicious_count = 0
    harmless_count = 0
    undetected_count = 0
    reputation_score = 0
    categories: List[str] = []
    engine_results: Dict[str, str] = {}
    scan_status = "UNKNOWN"
    summary_message = ""

    # Step 1: Check existing URL report using base64url encoding (no padding)
    try:
        url_bytes = target_url.encode("utf-8")
        url_id = base64.urlsafe_b64encode(url_bytes).decode("ascii").strip("=")
        vt_url_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        resp = requests.get(vt_url_endpoint, headers=headers, timeout=6.0)

        if resp.status_code == 200:
            scan_status = "EXISTING_REPORT"
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            harmless_count = stats.get("harmless", 0)
            undetected_count = stats.get("undetected", 0)
            reputation_score = data.get("reputation", 0)
            categories = list(data.get("categories", {}).values())[:5]

            analysis_results = data.get("last_analysis_results", {})
            for eng_name, eng_info in analysis_results.items():
                cat = eng_info.get("category")
                if cat in ("malicious", "suspicious"):
                    engine_results[eng_name] = eng_info.get("result") or cat

            summary_message = f"Existing URL report retrieved: {malicious_count} security engines flagged malicious, {suspicious_count} suspicious, {harmless_count} clean."

        elif resp.status_code == 404:
            # Report does not exist yet; request fresh scan
            scan_status = "FRESH_SCAN_REQUESTED"
            post_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": target_url},
                timeout=6.0
            )

            if post_resp.status_code in (200, 201):
                analysis_id = post_resp.json().get("data", {}).get("id")
                if analysis_id:
                    time.sleep(2.0)
                    an_resp = requests.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=headers,
                        timeout=6.0
                    )
                    if an_resp.status_code == 200:
                        an_data = an_resp.json().get("data", {}).get("attributes", {})
                        an_status = an_data.get("status")
                        stats = an_data.get("stats", {})
                        malicious_count = stats.get("malicious", 0)
                        suspicious_count = stats.get("suspicious", 0)
                        harmless_count = stats.get("harmless", 0)
                        undetected_count = stats.get("undetected", 0)
                        scan_status = f"ANALYSIS_{an_status.upper()}"
                        summary_message = f"Fresh URL scan requested (Analysis ID: {analysis_id}): status is {an_status} with {malicious_count} malicious detections."
            elif post_resp.status_code == 429:
                return {
                    "available": False,
                    "status": "RATE_LIMITED",
                    "source": "VirusTotal v3 API",
                    "message": "VirusTotal API rate limit exceeded (Free tier quota: 4 req/min). Please try again shortly.",
                    "malicious_count": 0, "suspicious_count": 0, "harmless_count": 0, "undetected_count": 0,
                    "reputation_score": 0, "categories": [], "engine_results": {}
                }

        elif resp.status_code == 429:
            return {
                "available": False,
                "status": "RATE_LIMITED",
                "source": "VirusTotal v3 API",
                "message": "VirusTotal API rate limit exceeded (Free tier quota: 4 req/min). Please try again shortly.",
                "malicious_count": 0, "suspicious_count": 0, "harmless_count": 0, "undetected_count": 0,
                "reputation_score": 0, "categories": [], "engine_results": {}
            }
        elif resp.status_code in (401, 403):
            return {
                "available": False,
                "status": "INVALID_KEY",
                "source": "VirusTotal v3 API",
                "message": "Configured VirusTotal API key is invalid or unauthorized.",
                "malicious_count": 0, "suspicious_count": 0, "harmless_count": 0, "undetected_count": 0,
                "reputation_score": 0, "categories": [], "engine_results": {}
            }

    except Exception as e:
        summary_message = f"VirusTotal URL query note: {str(e)}"

    # Step 2: Also query domain reputation for comprehensive intelligence
    try:
        dom_resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{hostname}",
            headers=headers,
            timeout=5.0
        )
        if dom_resp.status_code == 200:
            dom_attrs = dom_resp.json().get("data", {}).get("attributes", {})
            dom_stats = dom_attrs.get("last_analysis_stats", {})
            d_mal = dom_stats.get("malicious", 0)
            d_susp = dom_stats.get("suspicious", 0)
            if d_mal > malicious_count:
                malicious_count = d_mal
            if d_susp > suspicious_count:
                suspicious_count = d_susp
            reputation_score = dom_attrs.get("reputation", reputation_score)
            if not categories:
                categories = list(dom_attrs.get("categories", {}).values())[:5]
    except Exception:
        pass

    return {
        "available": True,
        "status": scan_status,
        "source": "VirusTotal v3 API",
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "harmless_count": harmless_count,
        "undetected_count": undetected_count,
        "reputation_score": reputation_score,
        "categories": categories,
        "engine_results": engine_results,
        "message": summary_message or f"Evaluated by security engines: {malicious_count} malicious, {suspicious_count} suspicious, {harmless_count} clean."
    }


def check_domain_reputation_optional(domain: str) -> Dict[str, Any]:
    """Backward-compatible wrapper for domain reputation check."""
    return check_virustotal_reputation(f"https://{domain}", domain)


def analyze_website_security(target_input: str) -> Dict[str, Any]:
    """
    Orchestrates complete safe defensive analysis workflow for a target website.
    Enforces SSRF prevention, checks HTTPS/TLS, queries headers, audits VirusTotal reputation,
    and synthesizes an objective overall assessment with explainable evidence:
      - 'Potentially Malicious'
      - 'No Threat Detected by Available Sources'
      - 'Unable to Determine'
    """
    check_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. URL Parsing & Sanitization
    is_valid_url, sanitized_url, hostname, port, url_err = sanitize_and_parse_url(target_input)
    if not is_valid_url:
        return {
            "success": False,
            "error_type": "URL_VALIDATION_ERROR",
            "error": url_err,
            "checked_at": check_timestamp,
            "overall_assessment": "Unable to Determine",
            "assessment_color": "#94a3b8",
            "summary": f"Target input validation failed: {url_err}",
            "evidence": {
                "summary": f"Target validation rejected: {url_err}",
                "items": [f"Input URL format error: {url_err}"],
                "sources_checked": ["URL Syntax Sanitizer"]
            }
        }

    # 2. SSRF & DNS-Rebinding Defense
    safe_dns, resolved_ips, dns_err = resolve_hostname_safely(hostname)
    if not safe_dns:
        is_ssrf = "ssrf" in dns_err.lower() or "prohibited" in dns_err.lower() or "blocked" in dns_err.lower()
        overall_assessment = "Potentially Malicious" if is_ssrf else "Unable to Determine"
        res_color = "#ef4444" if is_ssrf else "#94a3b8"
        return {
            "success": False,
            "error_type": "SSRF_DEFENSE_BLOCKED" if is_ssrf else "DNS_RESOLUTION_ERROR",
            "error": dns_err,
            "checked_at": check_timestamp,
            "input_url": target_input,
            "sanitized_url": sanitized_url,
            "hostname": hostname,
            "resolved_ips": resolved_ips,
            "overall_assessment": overall_assessment,
            "assessment_color": res_color,
            "severity": "HIGH" if is_ssrf else "LOW",
            "summary": f"SSRF Attack Blocked: Attempted access to prohibited destination ({dns_err})" if is_ssrf else f"DNS Resolution Failed: {dns_err}",
            "evidence": {
                "summary": "Prohibited destination blocked by Server-Side Request Forgery (SSRF) defense rules." if is_ssrf else "Domain could not be resolved via DNS.",
                "items": [
                    f"Blocked destination: {dns_err}",
                    "Inspection halted to prevent unauthorized probing of internal or cloud metadata infrastructure." if is_ssrf else "DNS lookup returned no valid records."
                ],
                "sources_checked": ["SSRF IP / DNS Validator"]
            },
            "tls_info": {"https_available": False, "cert_valid": False, "error": dns_err},
            "http_info": {"success": False, "error": dns_err, "headers_found": {}, "missing_headers": []},
            "reputation_info": {"available": False, "message": "Reputation lookup bypassed due to prohibited destination block." if is_ssrf else "DNS resolution failed"}
        }

    # 3. TLS Certificate Inspection (Port 443)
    tls_info = inspect_tls_certificate(hostname, port=443)

    # 4. HTTP Security Headers Audit (Passive GET with bounded redirect validation)
    http_info = inspect_http_security_headers(sanitized_url)

    # 5. VirusTotal API v3 Threat Intelligence
    reputation_info = check_virustotal_reputation(sanitized_url, hostname)

    # 6. Build Evidence Items and Concerns
    concerns: List[str] = []
    evidence_items: List[str] = []
    sources_checked = ["Safe DNS & IP Resolution"]

    # Evidence from Reachability & DNS
    if resolved_ips:
        evidence_items.append(f"Domain resolved to safe public IP address(es): `{', '.join(resolved_ips)}`.")

    # Evidence from TLS
    sources_checked.append("TLS/SSL Certificate Handshake (Port 443)")
    if tls_info.get("https_available") and tls_info.get("cert_valid"):
        days = tls_info.get("days_remaining", 0)
        issuer = tls_info.get("issuer", "Unknown CA")
        evidence_items.append(f"Valid HTTPS connection established. Certificate issued by **{issuer}** (expires in **{days} days**).")
    elif tls_info.get("is_expired"):
        days_rem = tls_info.get("days_remaining")
        if days_rem is not None:
            days_ago = abs(days_rem)
            concerns.append(f"TLS certificate EXPIRED {days_ago} days ago.")
            evidence_items.append(f"Cryptographic risk: TLS certificate is **EXPIRED** ({days_ago} days ago).")
        else:
            concerns.append("TLS certificate is EXPIRED.")
            evidence_items.append("Cryptographic risk: TLS certificate is **EXPIRED**.")
    elif not tls_info.get("https_available"):
        concerns.append("HTTPS is not accessible on standard port 443.")
        evidence_items.append("HTTPS port 443 is unreachable or connection was refused.")
    else:
        err = tls_info.get("error", "Invalid certificate")
        concerns.append(f"TLS certificate trust verification failed: {err}")
        evidence_items.append(f"TLS certificate trust verification failed: {err}")

    # Evidence from HTTP Security Headers
    sources_checked.append("HTTP Defensive Security Headers Audit")
    if http_info.get("success"):
        found = http_info.get("headers_found", {})
        missing = [m["header"] for m in http_info.get("missing_headers", [])]
        evidence_items.append(f"Defensive headers audit: **{len(found)}/6** recommended security headers present.")
        if "Strict-Transport-Security" in found:
            evidence_items.append("HTTP Strict Transport Security (HSTS) is active, enforcing encrypted browser connections.")
        else:
            concerns.append("Missing Strict-Transport-Security (HSTS) header.")
        if "Content-Security-Policy" in found:
            evidence_items.append("Content Security Policy (CSP) is active, restricting unauthorized script execution.")
        else:
            concerns.append("Missing Content-Security-Policy (CSP) header.")
    else:
        concerns.append(f"HTTP connection note: {http_info.get('error')}")
        evidence_items.append(f"HTTP request returned an issue: {http_info.get('error')}")

    # Evidence from VirusTotal v3 Reputation
    sources_checked.append("VirusTotal v3 Threat Intelligence Engine")
    if reputation_info.get("available"):
        mal_count = reputation_info.get("malicious_count", 0)
        susp_count = reputation_info.get("suspicious_count", 0)
        clean_count = reputation_info.get("harmless_count", 0)
        rep_score = reputation_info.get("reputation_score", 0)

        if mal_count > 0 or susp_count >= 2:
            concerns.append(f"🚨 Threat Intelligence: Flagged malicious by {mal_count} and suspicious by {susp_count} security engines.")
            evidence_items.append(f"**VirusTotal Alert:** Flagged by **{mal_count} security engine(s)** as malicious (Community reputation: {rep_score}).")
        else:
            evidence_items.append(f"VirusTotal query completed: **0/{mal_count + susp_count + clean_count}** security engines flagged threats (Community reputation: {rep_score}).")
    else:
        evidence_items.append(f"VirusTotal lookup: {reputation_info.get('message')}")

    # 7. Final Assessment Synthesis (Strictly one of the 3 required outcomes)
    if not http_info.get("success") and not tls_info.get("https_available"):
        overall_assessment = "Unable to Determine"
        assessment_color = "#94a3b8"  # Slate
        summary = "The target endpoint could not be reached safely or returned a network communication error."
    elif reputation_info.get("available") and (reputation_info.get("malicious_count", 0) > 0 or reputation_info.get("suspicious_count", 0) >= 2):
        overall_assessment = "Potentially Malicious"
        assessment_color = "#ef4444"  # Red
        summary = f"Flagged as malicious or suspicious by {reputation_info.get('malicious_count')} security engines on VirusTotal."
    elif (tls_info.get("is_expired") or (tls_info.get("https_available") and not tls_info.get("cert_valid"))):
        overall_assessment = "Potentially Malicious"
        assessment_color = "#ef4444"  # Red
        summary = "Severe cryptographic risk: TLS certificate is expired or failed trust verification."
    else:
        overall_assessment = "No Threat Detected by Available Sources"
        assessment_color = "#10b981"  # Green
        summary = "No verified threat flags identified by available sources. TLS connection verified and no malicious reputation indicators found."

    evidence = {
        "summary": summary,
        "items": evidence_items,
        "sources_checked": sources_checked,
        "tls_summary": "Valid HTTPS" if (tls_info.get("https_available") and tls_info.get("cert_valid")) else ("Expired / Invalid" if tls_info.get("is_expired") else "Unavailable"),
        "headers_summary": f"{len(http_info.get('headers_found', {}))}/6 Security Headers Present",
        "reputation_summary": reputation_info.get("message", "Reputation check skipped")
    }

    return {
        "success": True,
        "input_url": target_input,
        "sanitized_url": sanitized_url,
        "hostname": hostname,
        "resolved_ips": resolved_ips,
        "checked_at": check_timestamp,
        "tls_info": tls_info,
        "http_info": http_info,
        "reputation_info": reputation_info,
        "concerns": concerns,
        "overall_assessment": overall_assessment,
        "assessment_color": assessment_color,
        "summary": summary,
        "evidence": evidence,
        "disclaimer": "Defensive educational observation only. Missing headers do not prove malice; valid HTTPS does not guarantee website content safety."
    }


if __name__ == "__main__":
    print("Testing Website Threat Checker...")
    test_urls = ["https://example.com", "http://127.0.0.1", "http://169.254.169.254"]
    for u in test_urls:
        print(f"\nScanning: {u}")
        res = analyze_website_security(u)
        print("Success:", res.get("success"))
        print("Assessment:", res.get("overall_assessment"))
        print("Summary:", res.get("summary"))
