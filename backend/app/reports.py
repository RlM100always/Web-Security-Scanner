import io,json,html
from datetime import datetime,timezone
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak,KeepTogether

ACTIVE={"FAIL","WARNING","ERROR"}
SEVERITY_ORDER={"CRITICAL":5,"HIGH":4,"MEDIUM":3,"LOW":2,"INFO":1}

def _ctx(context=None):
    c=context or {}
    return {
      "assets":c.get("assets") or [],
      "asset_comparison":c.get("asset_comparison") or {},
      "standards_summary":c.get("standards_summary") or [],
      "policy":c.get("policy") or {},
      "target":c.get("target") or {},
      "zap":c.get("zap"),
      "generated_at":c.get("generated_at") or datetime.now(timezone.utc).isoformat(),
    }

def _active(findings):
    return [f for f in findings if f.get("status") in ACTIVE]

def _counts(findings):
    active=_active(findings)
    return {s:sum(1 for f in active if (f.get("severity") or "INFO").upper()==s) for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}

def _executive(scan,findings,comparison,context):
    counts=_counts(findings);active=sum(counts.values())
    return {
      "security_score":scan.get("score"),
      "active_findings":active,
      "severity_counts":counts,
      "new_findings":comparison.get("new",0),
      "fixed_findings":comparison.get("fixed",0),
      "unchanged_findings":comparison.get("unchanged",0),
      "assets_discovered":len(context["assets"]),
      "pages_scanned":scan.get("pages_scanned",0),
      "duration_ms":scan.get("duration_ms",0),
    }

def report_payload(scan,findings,comparison,context=None):
    c=_ctx(context);executive=_executive(scan,findings,comparison,c)
    ordered=sorted(findings,key=lambda f:(f.get("status") not in ACTIVE,-SEVERITY_ORDER.get((f.get("severity") or "INFO").upper(),0),f.get("title","")))
    return {
      "report":{"title":"SentinelScope Web Security Assessment","generated_at":c["generated_at"],"classification":"Authorised, non-destructive automated assessment"},
      "executive_summary":executive,
      "scan":scan,
      "target":c["target"],
      "policy":c["policy"],
      "comparison":comparison,
      "asset_comparison":c["asset_comparison"],
      "assets":c["assets"],
      "standards_summary":c["standards_summary"],
      "findings":ordered,
      "zap_comparison":c["zap"],
      "methodology":{
        "approach":"Bounded HTTP/TLS assessment with same-origin discovery and evidence-led configuration checks.",
        "safety":["Authorisation required before scanning","SSRF/private-network protections by default","Redirect destinations revalidated","Request, response-size, crawl-depth and page-count caps","No destructive exploitation, credential attacks, data extraction or denial-of-service behaviour"],
      },
      "limitations":[
        "Automated results require human review and may contain false positives or false negatives.",
        "The scanner does not prove complete OWASP, ASVS, WSTG or regulatory compliance.",
        "Business-logic, complex authorization, architecture, source-code-only and human-process weaknesses require manual assessment.",
        "Results describe the observed target state at scan time and can change with deployment, routing or application state."
      ],
    }

def as_json(scan,findings,comparison,context=None):
    return json.dumps(report_payload(scan,findings,comparison,context),indent=2,default=str)

def _h(value):
    return html.escape(str(value if value is not None else "—"))

def as_html(scan,findings,comparison,context=None):
    p=report_payload(scan,findings,comparison,context);x=p["executive_summary"];counts=x["severity_counts"]
    target=p["target"];policy=p["policy"];asset_diff=p["asset_comparison"] or {}
    finding_sections=[]
    for f in p["findings"]:
        standards="".join(f'<span class="tag">{_h(s)}</span>' for s in f.get("standards",[]))
        lifecycle=f.get("lifecycle_state") or f.get("status")
        finding_sections.append(f'''<article class="finding">
          <div class="finding-head"><span class="severity {_h((f.get("severity") or "info").lower())}">{_h(f.get("severity"))}</span><div><h3>{_h(f.get("title"))}</h3><p>{_h(f.get("url"))}</p></div><span class="state">{_h(lifecycle)}</span></div>
          <div class="finding-grid">
            <section><h4>Evidence</h4><pre>{_h(f.get("evidence"))}</pre><h4>Why it matters</h4><p>{_h(f.get("impact"))}</p><h4>Recommended remediation</h4><p>{_h(f.get("remediation"))}</p></section>
            <aside><dl><dt>Check ID</dt><dd>{_h(f.get("check_id"))}</dd><dt>Confidence</dt><dd>{_h(f.get("confidence"))}</dd><dt>Status</dt><dd>{_h(f.get("status"))}</dd><dt>Occurrences</dt><dd>{_h(f.get("occurrences") or "—")}</dd></dl><div>{standards or '<span class="tag">No mapping</span>'}</div></aside>
          </div></article>''')
    standards_rows="".join(f"<tr><td>{_h(s.get('standard'))}</td><td>{_h(s.get('mapped_checks'))}</td><td>{_h(s.get('PASS',0))}</td><td>{_h(s.get('WARNING',0))}</td><td>{_h(s.get('FAIL',0))}</td><td>{_h(s.get('ERROR',0))}</td></tr>" for s in p["standards_summary"])
    asset_rows="".join(f"<tr><td>{_h(a.get('url'))}</td><td>{_h(a.get('status_code'))}</td><td>{_h(a.get('kind'))}</td><td>{_h(a.get('depth'))}</td><td>{_h((a.get('metadata') or {}).get('elapsed_ms'))}</td></tr>" for a in p["assets"][:200])
    policy_rows="".join(f"<tr><td>{_h(k)}</td><td>{_h(', '.join(map(str,v)) if isinstance(v,list) else v)}</td></tr>" for k,v in policy.items())
    limits="".join(f"<li>{_h(v)}</li>" for v in p["limitations"])
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>SentinelScope Assessment Report</title>
<style>
:root{{--ink:#172235;--muted:#67768a;--line:#dde5ef;--blue:#1769ff;--bg:#f5f7fb;--card:#fff}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:13px Inter,system-ui,-apple-system,Segoe UI,sans-serif}}main{{max-width:1120px;margin:auto;padding:36px 24px 70px}}.cover{{background:#0b1729;color:#fff;border-radius:18px;padding:34px;margin-bottom:18px}}.cover small{{letter-spacing:.13em;color:#8ea4bf}}.cover h1{{font-size:31px;margin:10px 0 4px}}.cover p{{color:#aab8c9;margin:4px 0}}.score{{font-size:56px;font-weight:850;letter-spacing:-.05em;margin-top:25px}}.score span{{font-size:14px;color:#8192a8}}.metrics{{display:grid;grid-template-columns:repeat(5,1fr);gap:9px;margin:15px 0}}.metric,.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}}.metric small{{display:block;color:var(--muted);font-size:9px;letter-spacing:.07em}}.metric b{{display:block;font-size:23px;margin-top:5px}}h2{{font-size:18px;margin:28px 0 10px}}h3{{margin:0}}table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);border-radius:10px;overflow:hidden}}th,td{{padding:10px;border-bottom:1px solid #e9edf3;text-align:left;vertical-align:top;font-size:11px}}th{{background:#f8fafc;font-size:9px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}}.finding{{background:#fff;border:1px solid var(--line);border-radius:12px;margin:10px 0;overflow:hidden}}.finding-head{{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;padding:14px;border-bottom:1px solid #e9edf3}}.finding-head p{{font-size:10px;color:var(--muted);margin:4px 0 0;word-break:break-all}}.severity,.state,.tag{{display:inline-block;border-radius:999px;padding:5px 7px;font-size:8px;font-weight:850}}.severity.critical,.severity.high{{background:#ffeaec;color:#ae303b}}.severity.medium{{background:#fff1dd;color:#a76509}}.severity.low{{background:#eaf2ff;color:#2867ba}}.severity.info{{background:#eef1f5;color:#657287}}.state,.tag{{background:#eef3f8;color:#53647b}}.finding-grid{{display:grid;grid-template-columns:2fr 1fr;gap:20px;padding:16px}}h4{{font-size:9px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:13px 0 6px}}pre{{white-space:pre-wrap;word-break:break-word;background:#0e1929;color:#dce7f5;padding:11px;border-radius:8px;font:10px ui-monospace,monospace}}dl{{display:grid;grid-template-columns:1fr 1fr;gap:8px}}dt{{color:var(--muted);font-size:9px}}dd{{margin:0;font-weight:700;font-size:10px}}.tag{{margin:3px 3px 0 0}}ul{{line-height:1.6;color:var(--muted)}}.meta{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}@media(max-width:760px){{main{{padding:18px 10px}}.metrics{{grid-template-columns:1fr 1fr}}.finding-grid,.meta{{grid-template-columns:1fr}}.finding-head{{grid-template-columns:auto 1fr}}.finding-head>.state{{grid-column:1/-1;justify-self:start}}}}@media print{{body{{background:#fff}}main{{max-width:none;padding:0}}.cover{{break-after:avoid}}.finding{{break-inside:avoid}}}}
</style></head><body><main>
<section class="cover"><small>SENTINELSCOPE · SECURITY ASSESSMENT</small><h1>{_h(scan.get("target_url"))}</h1><p>Authorised, non-destructive automated assessment · generated {_h(p["report"]["generated_at"])}</p><div class="score">{_h(x["security_score"])}<span>/100</span></div><p>{_h(scan.get("profile","standard")).upper()} profile · {_h(x["pages_scanned"])} pages/assets · {_h(x["duration_ms"])} ms</p></section>
<section class="metrics"><div class="metric"><small>ACTIVE FINDINGS</small><b>{x["active_findings"]}</b></div><div class="metric"><small>CRITICAL/HIGH</small><b>{counts["CRITICAL"]+counts["HIGH"]}</b></div><div class="metric"><small>NEW</small><b>{x["new_findings"]}</b></div><div class="metric"><small>FIXED</small><b>{x["fixed_findings"]}</b></div><div class="metric"><small>ASSETS</small><b>{x["assets_discovered"]}</b></div></section>
<h2>Executive summary</h2><div class="meta"><div class="card"><b>Risk distribution</b><p>Critical {counts["CRITICAL"]} · High {counts["HIGH"]} · Medium {counts["MEDIUM"]} · Low {counts["LOW"]}</p><p>Compared with the preceding completed scan: {x["new_findings"]} new, {x["fixed_findings"]} fixed, {x["unchanged_findings"]} unchanged active findings.</p></div><div class="card"><b>Target context</b><p>Environment: {_h(target.get("environment","—"))}<br>Business criticality: {_h(target.get("criticality","—"))}<br>Verified ownership: {_h(target.get("verified","—"))}</p><p>Asset drift: +{_h((asset_diff.get("summary") or {}).get("added",0))} / -{_h((asset_diff.get("summary") or {}).get("removed",0))} / {_h((asset_diff.get("summary") or {}).get("changed",0))} changed.</p></div></div>
<h2>Assessment policy</h2><table><tr><th>Policy control</th><th>Value used for this scan</th></tr>{policy_rows or '<tr><td colspan="2">Default scan profile policy</td></tr>'}</table>
<h2>Standards-mapped evidence</h2><table><tr><th>Reference</th><th>Mapped checks</th><th>Pass</th><th>Warning</th><th>Fail</th><th>Error</th></tr>{standards_rows or '<tr><td colspan="6">No standards mapping recorded.</td></tr>'}</table>
<h2>Detailed findings</h2>{''.join(finding_sections) or '<div class="card">No findings were stored for this scan.</div>'}
<h2>Discovered asset inventory</h2><table><tr><th>URL</th><th>HTTP</th><th>Type</th><th>Depth</th><th>Latency</th></tr>{asset_rows or '<tr><td colspan="5">No assets recorded.</td></tr>'}</table>
<h2>Methodology & safety boundary</h2><div class="card"><p>{_h(p["methodology"]["approach"])}</p><ul>{''.join(f"<li>{_h(v)}</li>" for v in p["methodology"]["safety"])}</ul></div>
<h2>Limitations</h2><div class="card"><ul>{limits}</ul></div>
</main></body></html>'''

def _pdf_styles():
    styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SSSmall",parent=styles["BodyText"],fontName="Helvetica",fontSize=7.5,leading=10,textColor=colors.HexColor("#627187")))
    styles.add(ParagraphStyle(name="SSTitle",parent=styles["Title"],fontName="Helvetica-Bold",fontSize=22,leading=26,textColor=colors.HexColor("#122033"),spaceAfter=8))
    styles.add(ParagraphStyle(name="SSH2",parent=styles["Heading2"],fontName="Helvetica-Bold",fontSize=13,leading=16,textColor=colors.HexColor("#172235"),spaceBefore=14,spaceAfter=7))
    styles.add(ParagraphStyle(name="SSH3",parent=styles["Heading3"],fontName="Helvetica-Bold",fontSize=10,leading=13,textColor=colors.HexColor("#172235"),spaceBefore=8,spaceAfter=4))
    styles.add(ParagraphStyle(name="SSBody",parent=styles["BodyText"],fontName="Helvetica",fontSize=8.5,leading=12,textColor=colors.HexColor("#344258")))
    styles.add(ParagraphStyle(name="SSRight",parent=styles["SSSmall"],alignment=TA_RIGHT))
    return styles

def as_pdf(scan,findings,comparison,context=None):
    p=report_payload(scan,findings,comparison,context);x=p["executive_summary"];counts=x["severity_counts"];styles=_pdf_styles()
    out=io.BytesIO();doc=SimpleDocTemplate(out,pagesize=A4,rightMargin=18*mm,leftMargin=18*mm,topMargin=16*mm,bottomMargin=16*mm,title="SentinelScope Web Security Assessment")
    story=[]
    story += [Paragraph("SENTINELSCOPE · AUTHORISED SECURITY ASSESSMENT",styles["SSSmall"]),Spacer(1,4),Paragraph(html.escape(str(scan.get("target_url",""))),styles["SSTitle"]),
              Paragraph(f'Generated {html.escape(p["report"]["generated_at"])} · {html.escape(str(scan.get("profile","standard")).upper())} profile',styles["SSSmall"]),Spacer(1,12)]
    summary_data=[
      [Paragraph("<b>Security score</b>",styles["SSSmall"]),Paragraph("<b>Active findings</b>",styles["SSSmall"]),Paragraph("<b>Critical / High</b>",styles["SSSmall"]),Paragraph("<b>Assets</b>",styles["SSSmall"])],
      [str(x["security_score"]) if x["security_score"] is not None else "—",str(x["active_findings"]),str(counts["CRITICAL"]+counts["HIGH"]),str(x["assets_discovered"])]
    ]
    table=Table(summary_data,colWidths=[42*mm]*4)
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#edf3fb")),("TEXTCOLOR",(0,0),(-1,-1),colors.HexColor("#172235")),("GRID",(0,0),(-1,-1),.4,colors.HexColor("#d7e0eb")),("FONTNAME",(0,1),(-1,1),"Helvetica-Bold"),("FONTSIZE",(0,1),(-1,1),17),("ALIGN",(0,1),(-1,1),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("TOPPADDING",(0,0),(-1,-1),7),("BOTTOMPADDING",(0,0),(-1,-1),7)]))
    story += [table,Spacer(1,10),Paragraph("Executive summary",styles["SSH2"]),Paragraph(f'{x["new_findings"]} new · {x["fixed_findings"]} fixed · {x["unchanged_findings"]} unchanged active findings compared with the preceding completed scan. Target criticality: {html.escape(str(p["target"].get("criticality","—")))}; environment: {html.escape(str(p["target"].get("environment","—")))}.',styles["SSBody"])]
    story += [Paragraph("Assessment policy",styles["SSH2"])]
    pdata=[[Paragraph("<b>Control</b>",styles["SSSmall"]),Paragraph("<b>Value used</b>",styles["SSSmall"])]]
    for k,v in p["policy"].items():pdata.append([Paragraph(html.escape(str(k)),styles["SSSmall"]),Paragraph(html.escape(", ".join(map(str,v)) if isinstance(v,list) else str(v)),styles["SSSmall"])])
    if len(pdata)==1:pdata.append(["Profile defaults","No project override recorded"])
    pt=Table(pdata,colWidths=[55*mm,113*mm],repeatRows=1);pt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#edf3fb")),("GRID",(0,0),(-1,-1),.35,colors.HexColor("#d9e1eb")),("VALIGN",(0,0),(-1,-1),"TOP"),("FONTSIZE",(0,0),(-1,-1),7.5),("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5)]));story.append(pt)
    story += [Paragraph("Standards-mapped evidence",styles["SSH2"])]
    sdata=[["Reference","Checks","Pass","Warn","Fail","Error"]]+[[s.get("standard"),s.get("mapped_checks",0),s.get("PASS",0),s.get("WARNING",0),s.get("FAIL",0),s.get("ERROR",0)] for s in p["standards_summary"]]
    if len(sdata)==1:sdata.append(["No mapping",0,0,0,0,0])
    st=Table(sdata,colWidths=[78*mm,18*mm,18*mm,18*mm,18*mm,18*mm],repeatRows=1);st.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#edf3fb")),("GRID",(0,0),(-1,-1),.35,colors.HexColor("#d9e1eb")),("FONTSIZE",(0,0),(-1,-1),7),("ALIGN",(1,1),(-1,-1),"CENTER"),("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4)]));story.append(st)
    story += [PageBreak(),Paragraph("Detailed findings",styles["SSH2"])]
    for f in p["findings"]:
        title=f'[{html.escape(str(f.get("severity","INFO")))}] {html.escape(str(f.get("title","Finding")))} — {html.escape(str(f.get("status","")))}'
        standards=", ".join(map(str,f.get("standards") or [])) or "No mapping"
        box=[Paragraph(title,styles["SSH3"]),Paragraph(html.escape(str(f.get("url",""))),styles["SSSmall"]),
             Paragraph("<b>Evidence</b>",styles["SSSmall"]),Paragraph(html.escape(str(f.get("evidence","—"))).replace("\n","<br/>"),styles["SSBody"]),
             Paragraph("<b>Impact</b>",styles["SSSmall"]),Paragraph(html.escape(str(f.get("impact","—"))),styles["SSBody"]),
             Paragraph("<b>Remediation</b>",styles["SSSmall"]),Paragraph(html.escape(str(f.get("remediation","—"))),styles["SSBody"]),
             Paragraph(f'<b>Confidence:</b> {html.escape(str(f.get("confidence","—")))} · <b>Standards:</b> {html.escape(standards)}',styles["SSSmall"]),Spacer(1,7)]
        story.append(KeepTogether(box))
    story += [Paragraph("Asset inventory summary",styles["SSH2"]),Paragraph(f'{len(p["assets"])} assets were persisted for this scan. The full inventory and request metadata are included in the JSON/HTML report formats.',styles["SSBody"])]
    ad=p["asset_comparison"].get("summary") or {};story.append(Paragraph(f'Asset drift: {ad.get("added",0)} added · {ad.get("removed",0)} removed · {ad.get("changed",0)} changed.',styles["SSBody"]))
    story += [Paragraph("Methodology & limitations",styles["SSH2"]),Paragraph(html.escape(p["methodology"]["approach"]),styles["SSBody"])]
    for item in p["methodology"]["safety"]:story.append(Paragraph("• "+html.escape(item),styles["SSBody"]))
    story.append(Spacer(1,5))
    for item in p["limitations"]:story.append(Paragraph("• "+html.escape(item),styles["SSBody"]))
    def footer(canvas,doc):
        canvas.saveState();canvas.setStrokeColor(colors.HexColor("#dde5ef"));canvas.line(18*mm,12*mm,192*mm,12*mm);canvas.setFont("Helvetica",7);canvas.setFillColor(colors.HexColor("#6c7a8e"));canvas.drawString(18*mm,8*mm,"SentinelScope · authorised, non-destructive assessment · automated results require human review");canvas.drawRightString(192*mm,8*mm,f"Page {doc.page}");canvas.restoreState()
    doc.build(story,onFirstPage=footer,onLaterPages=footer);out.seek(0);return out.getvalue()
