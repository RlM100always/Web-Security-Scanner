import io,json,html
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

def as_json(scan,findings,comparison): return json.dumps({'scan':scan,'comparison':comparison,'findings':findings},indent=2)
def as_html(scan,findings,comparison):
    rows=''.join(f"<tr><td>{html.escape(f['severity'])}</td><td>{html.escape(f['title'])}</td><td>{html.escape(f['status'])}</td><td>{html.escape(f['url'])}</td></tr>" for f in findings)
    return f'''<!doctype html><meta charset=utf-8><title>Security Scan Report</title><style>body{{font:14px system-ui;max-width:1100px;margin:40px auto;color:#18212f}}h1{{font-size:28px}}.score{{font-size:48px;font-weight:800}}table{{border-collapse:collapse;width:100%}}td,th{{padding:10px;border-bottom:1px solid #ddd;text-align:left}}</style><h1>Web Security Scan Report</h1><p>{html.escape(scan['target_url'])}</p><div class=score>{scan.get('score','-')}/100</div><p>Profile: {scan['profile']} · Pages: {scan.get('pages_scanned','-')} · Duration: {scan.get('duration_ms','-')} ms</p><h2>Change summary</h2><p>New {comparison.get('new',0)} · Fixed {comparison.get('fixed',0)} · Unchanged {comparison.get('unchanged',0)}</p><h2>Findings</h2><table><tr><th>Severity</th><th>Finding</th><th>Status</th><th>URL</th></tr>{rows}</table><h2>Limitations</h2><p>This automated scanner cannot reliably determine business-logic flaws, complete authorization correctness, or source-code-only vulnerabilities.</p>'''
def as_pdf(scan,findings,comparison):
    out=io.BytesIO(); c=canvas.Canvas(out,pagesize=A4); w,h=A4; y=h-55
    c.setFont('Helvetica-Bold',18);c.drawString(50,y,'Web Security Scan Report');y-=30
    c.setFont('Helvetica',9);c.drawString(50,y,scan['target_url'][:95]);y-=24
    c.setFont('Helvetica-Bold',26);c.drawString(50,y,f"Security score: {scan.get('score','-')}/100");y-=35
    c.setFont('Helvetica',9);c.drawString(50,y,f"Profile: {scan['profile']} | Pages: {scan.get('pages_scanned','-')} | Duration: {scan.get('duration_ms','-')} ms");y-=24
    for f in findings:
        if y<85:c.showPage();y=h-55
        c.setFont('Helvetica-Bold',10);c.drawString(50,y,f"[{f['severity']}] {f['title']} — {f['status']}"[:100]);y-=14
        c.setFont('Helvetica',8);c.drawString(60,y,f['url'][:105]);y-=18
    c.setFont('Helvetica-Oblique',8);c.drawString(50,50,'Authorised, non-destructive assessment only. Automated results require human review.')
    c.save();out.seek(0);return out.getvalue()
