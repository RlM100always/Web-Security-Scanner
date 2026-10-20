import time
from urllib.parse import urlsplit
from .http_client import SafeHttpClient
from .crawler import crawl
from .checks import run_page_checks, run_transport_checks, SEV_WEIGHT, mk
from .models import ScanResult
from ..security.targets import validate_target

def calculate_score(findings):
    penalty=0
    for f in findings:
        if f.status in {'FAIL','WARNING'}: penalty += SEV_WEIGHT.get(f.severity,0) * (1 if f.status=='FAIL' else .5)
    return max(0, round(100-min(100,penalty)))

def run_scan(target, profile='standard', allow_private=False, progress=None):
    start=time.perf_counter(); target=validate_target(target,allow_private); emit=progress or (lambda *a,**k:None)
    client=SafeHttpClient(allow_private=allow_private)
    findings=[]; emit('VALIDATING_TARGET',5,'Target validated')
    findings.extend(run_transport_checks(target,client)); emit('DISCOVERING',20,'Transport checks complete')
    max_pages,max_depth={'quick':(1,0),'standard':(12,2),'lab':(20,2)}.get(profile,(12,2))
    pages=crawl(target,client,max_pages,max_depth); emit('SCANNING',35,f'Discovered {len(pages)} page(s)')
    if not pages:
        findings.append(mk('availability.http','Target Reachability','Availability','ERROR','HIGH','HIGH',target,'No page could be retrieved','Checks whether the target can be retrieved safely.','A scan cannot assess an unreachable target.','Verify the URL, network access and target availability.',['NIST SP 800-115']))
    for idx,(url,resp) in enumerate(pages,1):
        findings.extend(run_page_checks(url,resp)); emit('SCANNING',35+int(45*idx/max(1,len(pages))),f'Checked {url}')
    seen=set(); unique=[]
    for f in findings:
        if f.fingerprint not in seen: seen.add(f.fingerprint); unique.append(f)
    emit('ANALYZING',88,'Normalizing findings')
    score=calculate_score(unique); duration=round((time.perf_counter()-start)*1000)
    emit('GENERATING_REPORT',96,'Preparing result')
    return ScanResult(target,profile,len(pages),duration,score,unique,len(unique))
