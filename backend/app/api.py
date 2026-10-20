import threading
from flask import Blueprint,current_app,request,jsonify,Response
from .scanner.engine import run_scan
from .security.targets import validate_target,TargetValidationError
from .reports import as_json,as_html,as_pdf

def create_blueprint():
    bp=Blueprint('api',__name__)
    def repo():return current_app.extensions['repo']
    @bp.get('/dashboard')
    def dashboard():
        scans=repo().list_scans(20); completed=[s for s in scans if s['status']=='COMPLETED']; latest=completed[0] if completed else None
        return {'projects':len(repo().list_projects()),'targets':len(repo().list_targets()),'latest_scan':latest,'recent_scans':scans[:8]}
    @bp.route('/projects',methods=['GET','POST'])
    def projects():
        if request.method=='GET':return jsonify(repo().list_projects())
        d=request.get_json(force=True); name=(d.get('name') or '').strip()
        if not name:return {'error':'Project name is required'},400
        return repo().create_project(name,d.get('description','')),201
    @bp.route('/targets',methods=['GET','POST'])
    def targets():
        if request.method=='GET':return jsonify(repo().list_targets(request.args.get('project_id')))
        d=request.get_json(force=True)
        if not d.get('authorized'):return {'error':'You must confirm ownership or explicit authorization'},400
        try:url=validate_target(d.get('url'),current_app.config['SCANNER_ALLOW_PRIVATE'])
        except TargetValidationError as e:return {'error':str(e)},400
        return repo().create_target(d.get('project_id'),url,d.get('name') or url,True,bool(d.get('verified'))),201
    @bp.post('/scans')
    def scans_create():
        d=request.get_json(force=True); t=repo().get_target(d.get('target_id'))
        if not t:return {'error':'Target not found'},404
        if not t.get('authorized'):return {'error':'Target is not authorized'},403
        profile=d.get('profile','standard')
        if profile not in {'quick','standard','lab'}:return {'error':'Invalid profile'},400
        if profile=='lab' and not t.get('verified'):return {'error':'Lab profile requires a verified target'},403
        s=repo().create_scan(t['id'],t['url'],profile); app=current_app._get_current_object()
        def worker():
            with app.app_context():
                r=app.extensions['repo']
                try:
                    r.update_scan(s['id'],status='SCANNING',stage='VALIDATING_TARGET',progress=1)
                    def progress(stage,pct,msg):r.update_scan(s['id'],stage=stage,progress=pct,status='SCANNING')
                    result=run_scan(t['url'],profile,app.config['SCANNER_ALLOW_PRIVATE'],progress)
                    r.add_findings(s['id'],result.findings);r.update_scan(s['id'],status='COMPLETED',stage='COMPLETED',progress=100,score=result.score,pages_scanned=result.pages_scanned,duration_ms=result.duration_ms,completed_at=r.now())
                except Exception as e:r.update_scan(s['id'],status='FAILED',stage='FAILED',progress=100,error=str(e)[:1000],completed_at=r.now())
        threading.Thread(target=worker,daemon=True).start();return s,202
    @bp.get('/scans')
    def scans_list():return jsonify(repo().list_scans())
    @bp.get('/scans/<scan_id>')
    def scan_get(scan_id):
        s=repo().get_scan(scan_id)
        if not s:return {'error':'Scan not found'},404
        s['findings']=repo().findings(scan_id);s['comparison']=repo().comparison(scan_id);return s
    @bp.get('/scans/<scan_id>/report.<fmt>')
    def report(scan_id,fmt):
        s=repo().get_scan(scan_id)
        if not s:return {'error':'Scan not found'},404
        f=repo().findings(scan_id); comp=repo().comparison(scan_id)
        if fmt=='json':return Response(as_json(s,f,comp),mimetype='application/json')
        if fmt=='html':return Response(as_html(s,f,comp),mimetype='text/html')
        if fmt=='pdf':return Response(as_pdf(s,f,comp),mimetype='application/pdf',headers={'Content-Disposition':f'attachment; filename=scan-{scan_id}.pdf'})
        return {'error':'Unsupported format'},404
    return bp
