import ipaddress, os, socket
from urllib.parse import urlsplit, urlunsplit

BLOCKED_HOSTS={"localhost","localhost.localdomain","metadata.google.internal"}
BLOCKED_IPS={ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("100.100.100.200")}

class TargetValidationError(ValueError): pass

def normalize_url(raw: str) -> str:
    raw=(raw or "").strip()
    if not raw: raise TargetValidationError("Target URL is required")
    if "://" not in raw: raw="https://"+raw
    try:
        p=urlsplit(raw)
        port=p.port
        hostname=p.hostname
    except (ValueError,UnicodeError) as e:
        raise TargetValidationError(f"Malformed target URL: {e}") from None
    if p.scheme.lower() not in {"http","https"}: raise TargetValidationError("Only HTTP and HTTPS targets are allowed")
    if not hostname: raise TargetValidationError("A valid hostname is required")
    if p.username or p.password: raise TargetValidationError("Credentials in target URLs are not allowed")
    if port and port not in {80,443,8080,8000,8090,8443}: raise TargetValidationError("Target port is not permitted")
    path=p.path or "/"
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), path, p.query, ""))

def _unsafe_ip(ip: ipaddress._BaseAddress) -> bool:
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified or ip in BLOCKED_IPS

def validate_target(raw: str, allow_private: bool|None=None) -> str:
    url=normalize_url(raw)
    try:host=(urlsplit(url).hostname or "").lower().rstrip(".")
    except (ValueError,UnicodeError) as e:raise TargetValidationError(f"Malformed target URL: {e}") from None
    allow_private = (os.getenv("SCANNER_ALLOW_PRIVATE","0")=="1") if allow_private is None else allow_private
    if host in BLOCKED_HOSTS and not allow_private: raise TargetValidationError("Local or metadata hosts are blocked")
    try:
        literal=ipaddress.ip_address(host)
        if _unsafe_ip(literal) and not allow_private: raise TargetValidationError("Private, local, reserved or link-local IP targets are blocked")
    except ValueError:
        try: infos=socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except (socket.gaierror,UnicodeError) as e: raise TargetValidationError(f"DNS resolution failed: {e}") from None
        if not infos:raise TargetValidationError("DNS resolution returned no addresses")
        for info in infos:
            try:ip=ipaddress.ip_address(info[4][0].split("%",1)[0])
            except ValueError:raise TargetValidationError("DNS resolution returned an invalid IP address") from None
            if _unsafe_ip(ip) and not allow_private: raise TargetValidationError("Target resolves to a private, local, reserved or link-local address")
    return url

def same_origin(a: str,b: str)->bool:
    try:
        pa,pb=urlsplit(a),urlsplit(b)
        return (pa.scheme.lower(),(pa.hostname or "").lower(),pa.port or (443 if pa.scheme.lower()=='https' else 80))==(
            pb.scheme.lower(),(pb.hostname or "").lower(),pb.port or (443 if pb.scheme.lower()=='https' else 80)
        )
    except (ValueError,UnicodeError):
        return False
