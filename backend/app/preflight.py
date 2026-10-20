import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .security.targets import validate_target
from .scanner.http_client import SafeHttpClient


def _check(key, label, status, evidence, action=None):
    return {"key":key,"label":label,"status":status,"evidence":evidence,"action":action}


def _tls_details(url, timeout=5):
    p=urlsplit(url)
    if p.scheme!="https":
        return None
    host=p.hostname
    port=p.port or 443
    ctx=ssl.create_default_context()
    with socket.create_connection((host,port),timeout=timeout) as raw:
        with ctx.wrap_socket(raw,server_hostname=host) as sock:
            cert=sock.getpeercert()
            expiry=cert.get("notAfter")
            days=None
            if expiry:
                try:
                    expires=datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry),timezone.utc)
                    days=int((expires-datetime.now(timezone.utc)).total_seconds()/86400)
                except Exception:
                    pass
            return {
                "protocol":sock.version(),
                "cipher":sock.cipher()[0] if sock.cipher() else None,
                "expires_at":expiry,
                "days_remaining":days,
            }


def run_target_preflight(target, profile="standard", allow_private=False, timeout=5):
    """Non-destructive setup validation before an assessment is queued."""
    checks=[]
    result={
        "requested_url":target["url"],
        "profile":profile,
        "verified":bool(target.get("verified")),
        "checks":checks,
    }
    try:
        safe_url=validate_target(target["url"],allow_private)
        result["normalized_url"]=safe_url
        checks.append(_check("safe_destination","Safe destination","PASS",
            "URL, scheme, hostname, port and resolved destination passed the platform target-safety policy."))
    except Exception as e:
        checks.append(_check("safe_destination","Safe destination","BLOCKED",str(e),
            "Correct the target URL or deployment safety configuration before scanning."))
        result["status"]="BLOCKED"
        return result

    host=urlsplit(safe_url).hostname
    try:
        addresses=sorted({x[4][0] for x in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)})
        result["resolved_addresses"]=addresses
        checks.append(_check("dns","DNS resolution","PASS",", ".join(addresses[:8]) or "Resolved"))
    except Exception as e:
        checks.append(_check("dns","DNS resolution","BLOCKED",str(e),"Verify DNS and target availability."))
        result["status"]="BLOCKED"
        return result

    client=SafeHttpClient(timeout=timeout,max_bytes=131072,allow_private=allow_private)
    try:
        response=client.get(safe_url)
        result.update({
            "status_code":response.status_code,
            "final_url":response.url,
            "content_type":response.headers.get("Content-Type",""),
            "elapsed_ms":getattr(response,"_sentinel_elapsed_ms",None),
            "redirects":getattr(response,"_sentinel_redirects",[]),
            "response_truncated":bool(getattr(response,"_sentinel_truncated",False)),
        })
        status=response.status_code
        if status in {401,403}:
            checks.append(_check("reachability","HTTP reachability","WARN",
                f"HTTP {status}: target is reachable but anonymous assessment visibility is restricted.",
                "Confirm that unauthenticated coverage is intentional; SentinelScope does not bypass authentication."))
        elif status in {429,503}:
            checks.append(_check("reachability","HTTP reachability","WARN",
                f"HTTP {status}: target is reachable but is rate-limiting or temporarily unavailable.",
                "Review maintenance/rate-limit policy before running the assessment."))
        elif status>=500:
            checks.append(_check("reachability","HTTP reachability","WARN",
                f"HTTP {status}: target returned a server error.",
                "Resolve target availability issues for more representative results."))
        else:
            checks.append(_check("reachability","HTTP reachability","PASS",f"HTTP {status}"))

        redirects=result["redirects"]
        checks.append(_check("redirects","Redirect safety","PASS",
            f"{len(redirects)} redirect(s); final destination {response.url}"))
        ctype=(result["content_type"] or "").lower()
        if "html" in ctype or "json" in ctype or "xml" in ctype:
            checks.append(_check("content","Assessable content","PASS",result["content_type"] or "Content returned"))
        else:
            checks.append(_check("content","Assessable content","WARN",
                result["content_type"] or "No Content-Type header",
                "Confirm this target is the intended web application entry point."))
    except Exception as e:
        checks.append(_check("reachability","HTTP reachability","BLOCKED",str(e),
            "Verify DNS, TLS, firewall/proxy policy and target availability."))
        result["status"]="BLOCKED"
        return result
    finally:
        client.close()

    final_url=result.get("final_url") or safe_url
    if urlsplit(final_url).scheme=="https":
        checks.append(_check("https","HTTPS transport","PASS","Final destination uses HTTPS."))
        try:
            tls=_tls_details(final_url,timeout)
            result["tls"]=tls
            if tls:
                days=tls.get("days_remaining")
                tls_status="WARN" if days is not None and days<30 else "PASS"
                checks.append(_check("tls","TLS handshake",tls_status,
                    f"{tls.get('protocol')} · {tls.get('cipher')} · certificate days remaining: {days}",
                    "Renew the certificate before expiry." if tls_status=="WARN" else None))
        except Exception as e:
            checks.append(_check("tls","TLS handshake","WARN",str(e),
                "Review certificate chain, hostname and TLS configuration."))
    else:
        checks.append(_check("https","HTTPS transport","WARN","Final destination uses plaintext HTTP.",
            "Use HTTPS for representative production security assessment."))

    if profile=="lab" and not target.get("verified"):
        checks.append(_check("lab_eligibility","Lab profile eligibility","BLOCKED",
            "Lab profile requires successful ownership verification.",
            "Verify ownership using the DNS TXT or well-known-file workflow."))
    else:
        checks.append(_check("profile_eligibility","Profile eligibility","PASS",
            "Target meets the selected profile's authorization prerequisites."))

    if result.get("response_truncated"):
        checks.append(_check("response_budget","Response budget","WARN",
            "Preflight response exceeded the 128 KiB diagnostic budget and was truncated.",
            "This is not a scan failure; bounded assessment response limits still apply."))
    else:
        checks.append(_check("response_budget","Response budget","PASS","Diagnostic response stayed within the preflight budget."))

    statuses={x["status"] for x in checks}
    result["status"]="BLOCKED" if "BLOCKED" in statuses else ("WARN" if "WARN" in statuses else "READY")
    return result
