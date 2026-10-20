from dataclasses import dataclass, asdict, field
from typing import Any

@dataclass
class Finding:
    check_id: str
    title: str
    category: str
    status: str
    severity: str
    confidence: str
    url: str
    evidence: str
    description: str
    impact: str
    remediation: str
    standards: list[str]=field(default_factory=list)
    fingerprint: str=""
    metadata: dict[str, Any]=field(default_factory=dict)
    def to_dict(self): return asdict(self)

@dataclass
class Asset:
    url: str
    kind: str
    status_code: int | None
    content_type: str
    title: str
    depth: int
    size_bytes: int
    source_url: str | None = None
    metadata: dict[str, Any]=field(default_factory=dict)
    def to_dict(self): return asdict(self)

@dataclass
class ScanResult:
    target: str
    profile: str
    pages_scanned: int
    duration_ms: int
    score: int
    findings: list[Finding]
    checks_run: int
    assets: list[Asset]=field(default_factory=list)
    policy: dict[str, Any]=field(default_factory=dict)
    def to_dict(self):
        d=asdict(self)
        d["findings"]=[f.to_dict() for f in self.findings]
        d["assets"]=[a.to_dict() for a in self.assets]
        return d
