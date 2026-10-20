import re

MAPPINGS = [
    (r"content security policy|csp", "header.content-security-policy"),
    (r"x-content-type-options|mime sniff", "header.x-content-type-options"),
    (r"x-frame-options|anti-clickjacking|frame-ancestors", "header.frame"),
    (r"strict-transport-security|hsts", "header.strict-transport-security"),
    (r"cookie.*httponly", "cookie.httponly"),
    (r"cookie.*secure", "cookie.secure"),
    (r"cookie.*samesite", "cookie.samesite"),
    (r"cross.*origin|cors", "cors.policy"),
    (r"mixed content", "browser.mixed"),
    (r"server leaks|server header|x-powered-by", "disclosure.server"),
]

def map_alert(name: str) -> str | None:
    n = (name or "").lower()
    for pattern, check in MAPPINGS:
        if re.search(pattern, n):
            return check
    return None

def parse_zap_json(data):
    items=[]
    sites=data.get("site",[]) if isinstance(data,dict) else []
    if isinstance(sites,dict):sites=[sites]
    for site in sites:
        alerts=site.get("alerts",[]) or []
        if isinstance(alerts,dict):alerts=[alerts]
        for alert in alerts:
            base={
                "plugin_id":str(alert.get("pluginid") or alert.get("pluginId") or ""),
                "alert":alert.get("alert") or alert.get("name") or "Unnamed ZAP alert",
                "risk":alert.get("riskdesc") or alert.get("risk") or "Unknown",
                "confidence":alert.get("confidence") or "Unknown",
                "description":alert.get("desc") or alert.get("description") or "",
                "solution":alert.get("solution") or "",
            }
            base["mapped_check_id"]=map_alert(base["alert"])
            instances=alert.get("instances") or [{}]
            if isinstance(instances,dict):instances=[instances]
            for instance in instances:
                z=base.copy();z.update({"url":instance.get("uri") or instance.get("url") or site.get("@name") or "",
                    "param":instance.get("param") or "","evidence":instance.get("evidence") or ""})
                items.append(z)
    return items

def compare_with_scanner(scanner_findings, zap_items):
    scanner_active=[f for f in scanner_findings if f.get("status") in {"FAIL","WARNING","ERROR"}]
    own={f.get("check_id") for f in scanner_active}
    zap_mapped={z.get("mapped_check_id") for z in zap_items if z.get("mapped_check_id")}
    both=sorted(own & zap_mapped); scanner_only=sorted(own-zap_mapped); zap_only=sorted(zap_mapped-own)
    unmapped=[z for z in zap_items if not z.get("mapped_check_id")]
    return {"summary":{"scanner_active":len(scanner_active),"zap_alert_instances":len(zap_items),"mapped_overlap":len(both),
        "scanner_only":len(scanner_only),"zap_only":len(zap_only),"zap_unmapped":len(unmapped)},
        "both":both,"scanner_only":scanner_only,"zap_only":zap_only,"zap_unmapped":unmapped}
