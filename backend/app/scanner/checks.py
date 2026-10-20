import hashlib, re, ssl, socket
from datetime import datetime, timezone
from urllib.parse import urlsplit, urljoin
from bs4 import BeautifulSoup
from .models import Finding

SEV_WEIGHT={"INFO":0,"LOW":2,"MEDIUM":5,"HIGH":10,"CRITICAL":20}

def mk(check_id,title,category,status,severity,confidence,url,evidence,description,impact,remediation,standards,metadata=None):
    raw=f"{check_id}|{urlsplit(url).hostname}|{urlsplit(url).path}|{title}"
    return Finding(check_id,title,category,status,severity,confidence,url,evidence,description,impact,remediation,standards,hashlib.sha256(raw.encode()).hexdigest()[:24],metadata or {})

def header_check(resp,url,key,title,severity,standards,remediation):
    val=resp.headers.get(key)
    return mk('header.'+key.lower(),title,'Security Headers','PASS' if val else 'FAIL',severity if not val else 'INFO','HIGH',url,f"{key}: {val or 'not present'}",f"Checks whether the {key} response header is present.","Missing browser security controls can increase exposure to client-side attacks or unsafe browser behaviour.",remediation,standards)

def run_page_checks(url,resp):
    fs=[]; h=resp.headers; text=resp.text if 'text' in h.get('Content-Type','') or '<html' in resp.text[:500].lower() else ''
    fs += [
      header_check(resp,url,'Content-Security-Policy','Content Security Policy','MEDIUM',['OWASP WSTG-CLNT','OWASP ASVS V14'],'Define and test a restrictive Content-Security-Policy appropriate for the application.'),
      header_check(resp,url,'X-Content-Type-Options','MIME Sniffing Protection','LOW',['OWASP ASVS V14'],'Set X-Content-Type-Options: nosniff.'),
      header_check(resp,url,'Referrer-Policy','Referrer Policy','LOW',['OWASP ASVS V14'],'Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin.'),
      header_check(resp,url,'Permissions-Policy','Permissions Policy','LOW',['OWASP ASVS V14'],'Define a Permissions-Policy limiting unnecessary browser capabilities.'),
      header_check(resp,url,'Cross-Origin-Opener-Policy','Cross-Origin Opener Policy','LOW',['OWASP ASVS V14'],'Consider Cross-Origin-Opener-Policy where cross-origin isolation is appropriate.'),
      header_check(resp,url,'Cross-Origin-Resource-Policy','Cross-Origin Resource Policy','LOW',['OWASP ASVS V14'],'Consider Cross-Origin-Resource-Policy for sensitive resources.'),
    ]
    if urlsplit(url).scheme=='https':
        fs.append(header_check(resp,url,'Strict-Transport-Security','HTTP Strict Transport Security','MEDIUM',['OWASP WSTG-CRYP','OWASP ASVS V9'],'Set Strict-Transport-Security after validating HTTPS coverage.'))
    else:
        fs.append(mk('header.strict-transport-security','HTTP Strict Transport Security','Security Headers','NOT_APPLICABLE','INFO','HIGH',url,'Target page is HTTP','HSTS applies to HTTPS origins.','HSTS is evaluated only after HTTPS is enabled.','Enable HTTPS first, then deploy HSTS carefully.',['OWASP WSTG-CRYP']))
    frame=h.get('Content-Security-Policy','')+" "+h.get('X-Frame-Options','')
    fs.append(mk('header.frame','Frame Embedding Protection','Security Headers','PASS' if ('frame-ancestors' in frame.lower() or h.get('X-Frame-Options')) else 'FAIL','MEDIUM','HIGH',url,frame.strip() or 'No frame protection header observed','Checks anti-framing protections.','Missing protection can increase clickjacking exposure.','Use CSP frame-ancestors; retain X-Frame-Options where legacy support is needed.',['OWASP WSTG-CLNT-09','OWASP ASVS V14']))
    csp=h.get('Content-Security-Policy','')
    if csp:
        directives={}
        for part in csp.split(';'):
            bits=part.strip().split()
            if bits:directives[bits[0].lower()]=bits[1:]
        risky=[]
        flat=csp.lower()
        if "'unsafe-eval'" in flat:risky.append("unsafe-eval")
        if "'unsafe-inline'" in flat:risky.append("unsafe-inline")
        if any(v=="*" for values in directives.values() for v in values):risky.append("wildcard source")
        missing=[x for x in ['default-src','object-src','base-uri'] if x not in directives]
        state='WARNING' if risky or missing else 'PASS'
        fs.append(mk('csp.quality','Content Security Policy Quality','Security Headers',state,'MEDIUM' if state=='WARNING' else 'INFO','MEDIUM',url,
          f"Risky tokens: {', '.join(risky) or 'none'}; missing baseline directives: {', '.join(missing) or 'none'}",
          'Parses CSP directives rather than checking header presence only.',
          'Weak source expressions or missing baseline directives can substantially reduce CSP protection.',
          'Remove unsafe-eval where possible, minimize unsafe-inline, avoid broad wildcards, and define baseline directives appropriate to the application.',
          ['OWASP ASVS V14','OWASP WSTG-CLNT']))
    if urlsplit(url).scheme=='https' and h.get('Strict-Transport-Security'):
        hsts=h.get('Strict-Transport-Security','');m=re.search(r'max-age\s*=\s*(\d+)',hsts,re.I);age=int(m.group(1)) if m else 0
        weak=age<15552000
        fs.append(mk('hsts.quality','HSTS Policy Strength','Security Headers','WARNING' if weak else 'PASS','MEDIUM' if weak else 'INFO','HIGH',url,
          f"{hsts}; parsed max-age={age}",
          'Parses HSTS max-age and policy directives.',
          'A very short HSTS lifetime provides weaker downgrade protection.',
          'After validating HTTPS coverage, use an appropriately long max-age and evaluate includeSubDomains/preload deliberately.',
          ['OWASP ASVS V9','OWASP WSTG-CRYP']))
    server=h.get('Server') or h.get('X-Powered-By')
    fs.append(mk('disclosure.server','Technology Banner Exposure','Information Disclosure','WARNING' if server else 'PASS','LOW','MEDIUM',url,server or 'No obvious technology banner observed','Reviews response headers for technology/version disclosure.','Detailed banners can help attackers fingerprint software.','Remove unnecessary version or framework disclosure where practical.',['OWASP WSTG-INFO-02']))
    acao=h.get('Access-Control-Allow-Origin','')
    creds=h.get('Access-Control-Allow-Credentials','').lower()=='true'
    cors_bad=acao=='*' and creds
    fs.append(mk('cors.policy','CORS Policy Review','CORS','FAIL' if cors_bad else ('WARNING' if acao=='*' else 'PASS'),'HIGH' if cors_bad else ('LOW' if acao=='*' else 'INFO'),'HIGH',url,f"Access-Control-Allow-Origin: {acao or 'not present'}; credentials={creds}",'Reviews coarse CORS policy signals without exploitation.','Overly permissive cross-origin policy may expose browser-accessible data.','Restrict allowed origins and avoid credentialed wildcard-style configurations.',['OWASP WSTG-CONF']))
    for raw in resp.headers.get('Set-Cookie','').split(',') if resp.headers.get('Set-Cookie') else []:
        low=raw.lower(); name=raw.split('=',1)[0].strip() or 'cookie'
        for attr,cid,sev in [('secure','cookie.secure','MEDIUM'),('httponly','cookie.httponly','MEDIUM'),('samesite','cookie.samesite','LOW')]:
            ok=attr in low
            fs.append(mk(cid,f'{name}: {attr.title()} Attribute','Cookies','PASS' if ok else 'FAIL',sev if not ok else 'INFO','HIGH',url,raw[:300],f'Checks whether the {name} cookie includes {attr}.','Weak cookie attributes can increase session exposure.','Set appropriate Secure, HttpOnly and SameSite attributes for sensitive cookies.',['OWASP WSTG-SESS-02','OWASP ASVS V3']))
    if text:
        soup=BeautifulSoup(text,'html.parser')
        mixed=[]
        if urlsplit(url).scheme=='https':
            for tag,attr in [('script','src'),('img','src'),('link','href'),('iframe','src')]:
                mixed += [x.get(attr) for x in soup.find_all(tag) if x.get(attr,'').lower().startswith('http://')]
        fs.append(mk('browser.mixed','Mixed Content','Browser Security','FAIL' if mixed else 'PASS','MEDIUM' if mixed else 'INFO','HIGH',url,('; '.join(mixed[:5]) if mixed else 'No obvious HTTP subresources observed'),'Checks HTTPS pages for HTTP-loaded subresources.','Mixed content can weaken transport guarantees.','Serve all subresources over HTTPS.',['OWASP WSTG-CRYP']))
        forms=soup.find_all('form'); insecure=[]; csrf_missing=[]; password_get=[]
        for f in forms:
            action=urljoin(url,f.get('action') or url); method=(f.get('method') or 'get').lower()
            if urlsplit(action).scheme=='http': insecure.append(action)
            if method=='post' and not any(re.search(r'csrf|xsrf|token', (i.get('name') or ''),re.I) for i in f.find_all('input')): csrf_missing.append(action)
            if method=='get' and f.find('input',{'type':'password'}): password_get.append(action)
        fs.append(mk('forms.transport','Secure Form Submission','Forms','FAIL' if insecure else 'PASS','HIGH' if insecure else 'INFO','HIGH',url,('; '.join(insecure[:5]) if insecure else 'No insecure form actions observed'),'Checks forms for HTTP submission targets.','Sensitive form data could be exposed in transit.','Submit sensitive forms only to HTTPS endpoints.',['OWASP WSTG-CRYP']))
        fs.append(mk('forms.csrf','CSRF Token Heuristic','Forms','WARNING' if csrf_missing else 'PASS','MEDIUM' if csrf_missing else 'INFO','LOW',url,(f'{len(csrf_missing)} POST form(s) without obvious anti-CSRF token' if csrf_missing else 'No obvious missing token indicators'),'Heuristic only: looks for anti-CSRF token-like fields in POST forms.','State-changing forms without CSRF protection may be vulnerable.','Use framework-supported anti-CSRF protections and verify server-side.',['OWASP WSTG-SESS-05']))
        fs.append(mk('forms.password_get','Password Form Method','Forms','FAIL' if password_get else 'PASS','HIGH' if password_get else 'INFO','HIGH',url,(f'{len(password_get)} password form(s) use GET' if password_get else 'No password GET forms observed'),'Checks whether password fields are submitted using GET.','Credentials in URLs can leak through history and logs.','Submit credentials with POST over HTTPS.',['OWASP ASVS V2']))
        external_scripts=[]; no_sri=[]
        for sc in soup.find_all('script',src=True):
            src=urljoin(url,sc.get('src'))
            if urlsplit(src).hostname and urlsplit(src).hostname!=urlsplit(url).hostname:
                external_scripts.append(src)
                if not sc.get('integrity'): no_sri.append(src)
        fs.append(mk('browser.sri','External Script Integrity','Browser Security','WARNING' if no_sri else 'PASS','LOW' if no_sri else 'INFO','MEDIUM',url,(('; '.join(no_sri[:5])) if no_sri else 'No external scripts without integrity observed'),'Heuristically checks cross-origin script tags for Subresource Integrity.','Third-party script compromise can affect the application.','Use trusted dependencies and consider integrity metadata for static third-party scripts.',['OWASP ASVS V14']))
        password_inputs=soup.find_all('input',{'type':'password'}); weak_auto=[i for i in password_inputs if (i.get('autocomplete') or '').lower() not in {'current-password','new-password'}]
        fs.append(mk('forms.password_autocomplete','Password Autocomplete Semantics','Forms','WARNING' if weak_auto else 'PASS','LOW' if weak_auto else 'INFO','MEDIUM',url,(f'{len(weak_auto)} password field(s) lack explicit autocomplete semantics' if weak_auto else 'Password autocomplete semantics look explicit or no password fields exist'),'Reviews password fields for modern autocomplete hints.','Correct semantics improve password-manager behavior and reduce user workarounds.','Use autocomplete=current-password or new-password as appropriate.',['OWASP ASVS V2']))
        cross_origin=[];sensitive_get=[]
        origin_host=urlsplit(url).hostname
        for f in forms:
            action=urljoin(url,f.get('action') or url);method=(f.get('method') or 'get').lower()
            has_sensitive=bool(f.find('input',{'type':'password'}) or any(re.search(r'email|token|secret|account|card|phone',i.get('name') or '',re.I) for i in f.find_all('input')))
            if has_sensitive and urlsplit(action).hostname and urlsplit(action).hostname!=origin_host:cross_origin.append(action)
            if has_sensitive and method=='get':sensitive_get.append(action)
        fs.append(mk('forms.cross_origin','Cross-Origin Sensitive Form Action','Forms','WARNING' if cross_origin else 'PASS','MEDIUM' if cross_origin else 'INFO','MEDIUM',url,
          '; '.join(cross_origin[:5]) if cross_origin else 'No sensitive-looking forms submit cross-origin',
          'Checks whether forms containing sensitive-looking fields submit to another origin.',
          'Cross-origin form submission can make trust boundaries harder to review and may expose sensitive data if misconfigured.',
          'Review cross-origin form destinations and keep sensitive authentication/payment submission within explicitly trusted origins.',
          ['OWASP ASVS V2','OWASP WSTG-INFO']))
        fs.append(mk('forms.sensitive_get','Sensitive Data in GET Form','Forms','FAIL' if sensitive_get else 'PASS','HIGH' if sensitive_get else 'INFO','HIGH',url,
          '; '.join(sensitive_get[:5]) if sensitive_get else 'No sensitive-looking GET forms observed',
          'Checks for sensitive-looking form fields submitted using GET.',
          'GET parameters can be retained in browser history, analytics, referrers and intermediary logs.',
          'Use POST over HTTPS for sensitive form submissions and avoid secrets in URLs.',
          ['OWASP ASVS V8','OWASP WSTG-INFO']))
        if password_inputs:
            cache=(h.get('Cache-Control') or '').lower()
            safe_cache='no-store' in cache
            fs.append(mk('cache.sensitive_page','Sensitive Page Cache Policy','Browser Security','WARNING' if not safe_cache else 'PASS','LOW' if not safe_cache else 'INFO','MEDIUM',url,
              f"Cache-Control: {h.get('Cache-Control') or 'not present'}",
              'Reviews cache-control on pages containing password fields.',
              'Sensitive authenticated content may persist in browser or intermediary caches when policy is weak.',
              'For genuinely sensitive responses, evaluate Cache-Control: no-store and related caching controls.',
              ['OWASP ASVS V8']))
        comments=' '.join(str(c) for c in soup.find_all(string=lambda t:isinstance(t,str) and ('todo' in t.lower() or 'fixme' in t.lower())))
        fs.append(mk('disclosure.comments','Potential Developer Comment Disclosure','Information Disclosure','WARNING' if comments else 'PASS','LOW' if comments else 'INFO','LOW',url,(comments[:300] if comments else 'No obvious TODO/FIXME disclosure observed'),'Looks for obvious development markers in rendered HTML.','Developer comments can reveal implementation details.','Remove sensitive development comments from production output.',['OWASP WSTG-INFO']))
    return fs

def run_transport_checks(url,client):
    fs=[]; p=urlsplit(url)
    if p.scheme=='https':
        fs.append(mk('transport.https','HTTPS Transport','Transport Security','PASS','INFO','HIGH',url,'Target uses HTTPS','Checks whether the submitted target uses HTTPS.','HTTPS protects data in transit.','Keep HTTPS enabled and redirect HTTP traffic to HTTPS.',['OWASP WSTG-CRYP-01']))
        try:
            ctx=ssl.create_default_context(); port=p.port or 443
            with socket.create_connection((p.hostname,port),timeout=5) as sock:
                with ctx.wrap_socket(sock,server_hostname=p.hostname) as ssock:
                    cert=ssock.getpeercert();version=ssock.version();expiry=cert.get('notAfter');cipher=ssock.cipher()
            expiry_days=None
            if expiry:
                try:expiry_days=int((datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry),timezone.utc)-datetime.now(timezone.utc)).total_seconds()/86400)
                except Exception:expiry_days=None
            fs.append(mk('tls.certificate','TLS Certificate Validation','Transport Security','PASS','INFO','HIGH',url,f'TLS={version}; expires={expiry}','Performs a standard certificate and hostname validated TLS handshake.','Invalid certificates undermine transport authenticity.','Use a trusted, hostname-valid, non-expired certificate.',['OWASP WSTG-CRYP-01']))
            weak=version in {'TLSv1','TLSv1.1'}
            fs.append(mk('tls.expiry','TLS Certificate Expiry','Transport Security','WARNING' if expiry_days is not None and expiry_days<30 else 'PASS','MEDIUM' if expiry_days is not None and expiry_days<30 else 'INFO','HIGH',url,
              f"Certificate expires {expiry}; days remaining={expiry_days}",
              'Calculates remaining certificate validity from the validated TLS handshake.',
              'Near-expiry certificates can cause service outages and emergency rotation risk.',
              'Automate certificate renewal and alert well before expiry.',
              ['OWASP WSTG-CRYP-01']))
            fs.append(mk('tls.cipher','TLS Negotiated Cipher','Transport Security','PASS','INFO','MEDIUM',url,
              f"Protocol={version}; cipher={cipher}",
              'Records the protocol and cipher selected by a validated TLS handshake.',
              'Cipher evidence supports configuration review and regression comparison.',
              'Maintain modern server-side TLS configuration and periodically review supported cipher suites.',
              ['OWASP WSTG-CRYP']))
            fs.append(mk('tls.version','TLS Protocol Version','Transport Security','FAIL' if weak else 'PASS','HIGH' if weak else 'INFO','HIGH',url,f'Negotiated protocol: {version}','Checks the negotiated TLS protocol version.','Legacy TLS versions provide weaker security guarantees.','Disable TLS 1.0/1.1 and prefer modern TLS.',['OWASP WSTG-CRYP']))
        except Exception as e:
            fs.append(mk('tls.certificate','TLS Certificate Validation','Transport Security','FAIL','HIGH','HIGH',url,str(e)[:300],'Attempts a certificate-validating TLS handshake.','Handshake or certificate errors can undermine transport security.','Correct certificate chain, hostname, expiry and TLS configuration.',['OWASP WSTG-CRYP-01']))
    else:
        fs.append(mk('transport.https','HTTPS Transport','Transport Security','FAIL','HIGH','HIGH',url,'Target uses HTTP','Checks whether the submitted target uses HTTPS.','Unencrypted HTTP exposes traffic to interception and modification.','Enable HTTPS and redirect HTTP requests to HTTPS.',['OWASP WSTG-CRYP-01']))
        try:
            r=client.get(url); final=r.url
            fs.append(mk('transport.redirect','HTTP to HTTPS Redirect','Transport Security','PASS' if urlsplit(final).scheme=='https' else 'FAIL','MEDIUM','HIGH',url,f'Final URL: {final}','Checks whether HTTP traffic is upgraded to HTTPS.','Without redirection, users may remain on plaintext HTTP.','Redirect all HTTP requests to HTTPS.',['OWASP WSTG-CRYP']))
        except Exception as e:
            fs.append(mk('transport.redirect','HTTP to HTTPS Redirect','Transport Security','ERROR','MEDIUM','MEDIUM',url,str(e)[:300],'Checks HTTP-to-HTTPS upgrade behaviour.','Unable to verify redirect behaviour.','Review target availability and redirect configuration.',['OWASP WSTG-CRYP']))
    return fs


def run_origin_checks(url,client):
    fs=[];origin='https://sentinelscope.invalid'
    try:
        r=client.get(url,headers={'Origin':origin})
        acao=(r.headers.get('Access-Control-Allow-Origin') or '').strip()
        creds=(r.headers.get('Access-Control-Allow-Credentials') or '').lower()=='true'
        reflected=acao==origin
        bad=reflected and creds
        fs.append(mk('cors.origin_reflection','Arbitrary Origin CORS Reflection','CORS','FAIL' if bad else ('WARNING' if reflected else 'PASS'),
          'HIGH' if bad else ('MEDIUM' if reflected else 'INFO'),'HIGH',url,
          f"Sent Origin={origin}; ACAO={acao or 'not present'}; credentials={creds}",
          'Sends a benign synthetic Origin header and observes whether it is reflected by the server.',
          'Arbitrary origin reflection can expose browser-readable responses, especially when credentials are allowed.',
          'Use an explicit allow-list and validate Origin values server-side; never reflect arbitrary origins for credentialed responses.',
          ['OWASP WSTG-CONF','OWASP ASVS V14']))
    except Exception as e:
        fs.append(mk('cors.origin_reflection','Arbitrary Origin CORS Reflection','CORS','ERROR','LOW','LOW',url,str(e)[:300],
          'Attempts a benign Origin reflection check.','The scanner could not evaluate dynamic CORS behavior.','Review CORS manually if relevant.',['OWASP WSTG-CONF']))
    try:
        r=client.options(url,headers={'Origin':origin,'Access-Control-Request-Method':'POST'})
        allow=(r.headers.get('Allow') or '')+','+(r.headers.get('Access-Control-Allow-Methods') or '')
        methods={x.strip().upper() for x in allow.split(',') if x.strip()}
        risky=sorted(methods & {'TRACE','CONNECT'})
        fs.append(mk('http.methods','Advertised HTTP Methods','Configuration','WARNING' if risky else 'PASS','MEDIUM' if risky else 'INFO','MEDIUM',url,
          f"Advertised methods: {', '.join(sorted(methods)) or 'none'}; risky: {', '.join(risky) or 'none'}",
          'Uses OPTIONS metadata only; it does not execute destructive methods.',
          'Unexpectedly exposed methods can expand the application attack surface.',
          'Disable unnecessary HTTP methods at the application and reverse-proxy layers.',
          ['OWASP WSTG-CONF-06']))
    except Exception as e:
        fs.append(mk('http.methods','Advertised HTTP Methods','Configuration','ERROR','LOW','LOW',url,str(e)[:300],
          'Reviews OPTIONS-advertised methods.','Method exposure could not be evaluated.','Review allowed HTTP methods manually.',['OWASP WSTG-CONF-06']))
    try:
        p=urlsplit(url);security_url=f"{p.scheme}://{p.netloc}/.well-known/security.txt";r=client.get(security_url)
        text=r.text[:12000] if r.status_code==200 else ''
        contact=bool(re.search(r'^Contact\s*:',text,re.I|re.M));expires=bool(re.search(r'^Expires\s*:',text,re.I|re.M))
        status='PASS' if r.status_code==200 and contact else ('WARNING' if r.status_code==200 else 'INFO')
        fs.append(mk('wellknown.security_txt','Security.txt Disclosure Channel','Governance',status,'LOW' if status=='WARNING' else 'INFO','HIGH',security_url,
          f"HTTP {r.status_code}; Contact={contact}; Expires={expires}",
          'Checks the standardized /.well-known/security.txt security contact location.',
          'A maintained security.txt improves vulnerability-report routing but is not itself a security boundary.',
          'Publish an RFC 9116-style security.txt with Contact and appropriate Expires metadata if the organization supports external reporting.',
          ['RFC 9116']))
    except Exception as e:
        fs.append(mk('wellknown.security_txt','Security.txt Disclosure Channel','Governance','INFO','INFO','LOW',url,str(e)[:300],
          'Checks the standardized security contact file.','No conclusion could be drawn.','Consider publishing security.txt if appropriate.',['RFC 9116']))
    return fs
