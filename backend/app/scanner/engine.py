import time
from urllib.parse import urlsplit
from bs4 import BeautifulSoup
from .http_client import SafeHttpClient
from .crawler import crawl
from .checks import run_page_checks,run_transport_checks,run_origin_checks,SEV_WEIGHT,mk
from .models import ScanResult,Asset
from ..security.targets import validate_target

PROFILE_DEFAULTS={
    "quick":{"max_pages":1,"max_depth":0,"request_delay_ms":0},
    "standard":{"max_pages":20,"max_depth":2,"request_delay_ms":100},
    "lab":{"max_pages":50,"max_depth":3,"request_delay_ms":100},
}

def calculate_score(findings):
    penalty=0
    for f in findings:
        if f.status in {"FAIL","WARNING"}:penalty+=SEV_WEIGHT.get(f.severity,0)*(1 if f.status=="FAIL" else .5)
    return max(0,round(100-min(100,penalty)))

def _asset(url,resp,depth,source):
    ctype=(resp.headers.get("Content-Type","") or "").split(";",1)[0].strip().lower()
    kind="html" if "html" in ctype else ("json" if "json" in ctype else ("xml" if "xml" in ctype else "resource"))
    title=""
    if kind=="html":
        try:
            soup=BeautifulSoup(resp.text,"html.parser")
            title=(soup.title.string or "").strip()[:200] if soup.title and soup.title.string else ""
        except Exception:pass
    return Asset(url=url,kind=kind,status_code=getattr(resp,"status_code",None),content_type=ctype,title=title,depth=depth,
                 size_bytes=len(getattr(resp,"content",b"") or b""),source_url=source,
                 metadata={"server":resp.headers.get("Server"),"cache_control":resp.headers.get("Cache-Control"),
                           "redirects":getattr(resp,"_sentinel_redirects",[]),"truncated":getattr(resp,"_sentinel_truncated",False),
                           "elapsed_ms":getattr(resp,"_sentinel_elapsed_ms",None)})

def normalize_policy(profile,policy=None):
    base=dict(PROFILE_DEFAULTS.get(profile,PROFILE_DEFAULTS["standard"]))
    p=policy or {}
    if profile=="quick":
        base["max_pages"]=1
        base["max_depth"]=0
    else:
        base["max_pages"]=max(1,min(int(p.get("max_pages",base["max_pages"])),200))
        base["max_depth"]=max(0,min(int(p.get("max_depth",base["max_depth"])),5))
    base["request_delay_ms"]=max(0,min(int(p.get("request_delay_ms",base["request_delay_ms"])),5000))
    base["include_paths"]=[str(x)[:200] for x in p.get("include_paths",[])][:30]
    base["exclude_paths"]=[str(x)[:200] for x in p.get("exclude_paths",[])][:30]
    base["disabled_checks"]=set(str(x) for x in p.get("disabled_checks",[]))
    return base

def run_scan(target,profile="standard",allow_private=False,progress=None,policy=None):
    start=time.perf_counter();target=validate_target(target,allow_private);emit=progress or (lambda *a,**k:None)
    policy=normalize_policy(profile,policy)
    client=SafeHttpClient(allow_private=allow_private)
    findings=[];assets=[];emit("VALIDATING_TARGET",5,"Target validated")
    findings.extend(run_transport_checks(target,client));emit("DISCOVERING",15,"Transport checks complete")
    if profile!="quick":findings.extend(run_origin_checks(target,client))
    emit("DISCOVERING",22,"Origin-level configuration checks complete")
    pages=crawl(target,client,policy["max_pages"],policy["max_depth"],policy["include_paths"],policy["exclude_paths"],policy["request_delay_ms"])
    emit("SCANNING",30,f"Discovered {len(pages)} in-scope asset(s)")
    if not pages:
        findings.append(mk("availability.http","Target Reachability","Availability","ERROR","HIGH","HIGH",target,"No page could be retrieved","Checks whether the target can be retrieved safely.","A scan cannot assess an unreachable target.","Verify the URL, network access and target availability.",["NIST SP 800-115"]))
    for idx,(url,resp,depth,source) in enumerate(pages,1):
        assets.append(_asset(url,resp,depth,source))
        findings.extend(run_page_checks(url,resp))
        emit("SCANNING",30+int(50*idx/max(1,len(pages))),f"Checked {url}")
    disabled=policy["disabled_checks"]
    if disabled:findings=[f for f in findings if f.check_id not in disabled]
    seen=set();unique=[]
    for f in findings:
        if f.fingerprint not in seen:seen.add(f.fingerprint);unique.append(f)
    emit("ANALYZING",88,"Normalizing findings and asset inventory")
    score=calculate_score(unique);duration=round((time.perf_counter()-start)*1000)
    emit("GENERATING_REPORT",96,"Preparing result")
    serial_policy={k:(sorted(v) if isinstance(v,set) else v) for k,v in policy.items()}
    return ScanResult(target,profile,len(pages),duration,score,unique,len(unique),assets,serial_policy)
