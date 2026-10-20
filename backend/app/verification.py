import secrets
from urllib.parse import urlsplit, urljoin
from .scanner.http_client import SafeHttpClient

def make_verification(target_url, method):
    token="sentinelscope-verification="+secrets.token_urlsafe(24)
    host=urlsplit(target_url).hostname
    if method=="file":
        instructions=f"Create /.well-known/sentinelscope-verification.txt on {host} containing exactly: {token}"
    elif method=="dns":
        instructions=f"Create a TXT record at _sentinelscope.{host} containing: {token}"
    else:
        raise ValueError("Verification method must be file or dns")
    return token,instructions

def check_file(target_url, token, allow_private=False):
    base=f"{urlsplit(target_url).scheme}://{urlsplit(target_url).netloc}/"
    url=urljoin(base,".well-known/sentinelscope-verification.txt")
    with SafeHttpClient(allow_private=allow_private) as client:
        r=client.get(url)
        text=(r.text or "").strip()
        return token in text, f"GET {url} returned HTTP {r.status_code}; token {'found' if token in text else 'not found'}"

def check_dns(target_url, token):
    host=urlsplit(target_url).hostname
    qname=f"_sentinelscope.{host}"
    try:
        import dns.resolver
    except ImportError as e:
        raise RuntimeError("DNS verification requires the dnspython dependency") from e
    answers=dns.resolver.resolve(qname,"TXT")
    values=[]
    for rdata in answers:
        txt="".join(part.decode() if isinstance(part,bytes) else str(part) for part in getattr(rdata,"strings",[])) or rdata.to_text().strip('"')
        values.append(txt)
    return token in values, f"TXT {qname}: "+("; ".join(values) if values else "no values")
