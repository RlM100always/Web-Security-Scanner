import React,{useEffect,useState}from'react';
import{ShieldCheck,Menu,X,ArrowRight,CheckCircle2,Radar,FolderKanban,TriangleAlert,History,KeyRound,Database,Users,FileText,Globe2,LockKeyhole,Workflow,Search,Activity,Braces,BookOpen,ChevronRight,ServerCog,GitCompareArrows,Webhook}from'lucide-react';
import'./public.css';import'./public-enterprise.css';

const links=[['Product','/product'],['Solutions','/solutions'],['Enterprise','/enterprise'],['Security','/security'],['Developers','/developers'],['Docs','/docs']];

export default function PublicSite({path='/'}:{path?:string}){
  const[open,setOpen]=useState(false);
  const page=path.replace(/^\//,'')||'home';
  return <div className="publicSite">
    <header className="publicNav">
      <a className="publicBrand" href="/"><span><ShieldCheck/></span><div><b>SentinelScope</b><small>Web Security Assessment Platform</small></div></a>
      <nav className={open?'open':''}>{links.map(([n,h])=><a key={h} className={path===h?'active':''} href={h}>{n}</a>)}</nav>
      <div className="publicActions"><a className="textLink" href="/login">Sign in</a><a className="publicPrimary" href="/signup">Start workspace <ArrowRight/></a><button className="publicMenu" onClick={()=>setOpen(!open)} aria-label="Toggle navigation">{open?<X/>:<Menu/>}</button></div>
    </header>
    {page==='home'?<Home/>:page==='status'?<StatusPage/>:<StaticPage page={page}/>}
    <footer className="publicFooter"><div><a className="publicBrand" href="/"><span><ShieldCheck/></span><div><b>SentinelScope</b><small>Authorised, non-destructive assessment</small></div></a><p>Designed for explainable web-security assessment, remediation tracking and repeatable evidence.</p></div><div className="footerGrid"><div><b>Platform</b><a href="/product">Product</a><a href="/features">Features</a><a href="/workflow">Workflow</a><a href="/solutions">Solutions</a></div><div><b>Enterprise</b><a href="/enterprise">Enterprise controls</a><a href="/integrations">Integrations</a><a href="/reports">Reporting</a><a href="/deployment">Deployment model</a></div><div><b>Developers</b><a href="/developers">Developer platform</a><a href="/api">API access</a><a href="/architecture">Architecture</a><a href="/scanner-checks">Scanner checks</a></div><div><b>Trust</b><a href="/trust">Trust center</a><a href="/status">Platform status</a><a href="/security">Security model</a><a href="/responsible-use">Responsible use</a><a href="/standards">Standards</a></div><div><b>Workspace</b><a href="/login">Sign in</a><a href="/signup">Create account</a></div></div><small className="footerNote">Use only against systems you own or are explicitly authorised to assess. SentinelScope intentionally avoids destructive exploitation, credential attacks and denial-of-service behaviour.</small></footer>
  </div>
}

function Home(){
  return <main>
    <section className="publicHero">
      <div className="heroCopy"><div className="heroKicker"><span></span> EVIDENCE-FIRST APPLICATION SECURITY</div><h1>Turn web-security checks into a <em>managed remediation workflow.</em></h1><p>Discover web assets, run bounded authorised assessments, prioritise findings, assign remediation, verify fixes and preserve standards-mapped evidence from one workspace.</p><div className="heroCtas"><a className="publicPrimary large" href="/signup">Create secure workspace <ArrowRight/></a><a className="publicSecondary" href="/product">Explore the platform</a></div><div className="heroTrust"><span><CheckCircle2/> Target authorisation controls</span><span><CheckCircle2/> SSRF-safe bounded scanning</span><span><CheckCircle2/> Persistent finding lifecycle</span></div></div>
      <ProductPreview/>
    </section>
    <section className="logoStrip"><span>BUILT AROUND</span><b>OWASP WSTG</b><b>OWASP ASVS</b><b>Evidence-led findings</b><b>SQLite WAL durability</b><b>Responsive PWA</b></section>
    <section className="publicSection"><SectionHead eyebrow="OPERATING MODEL" title="Security work should move, not sit in a report." text="SentinelScope connects discovery, assessment, triage and verification so every finding has context, ownership and a next action."/><div className="workflowRail">{[
      ['01','Discover','Build a persistent inventory of in-scope pages and response metadata.',Globe2],
      ['02','Assess','Run policy-bound, non-destructive checks with evidence and confidence.',Radar],
      ['03','Triage','Assign owners, due dates, state, comments and risk decisions.',TriangleAlert],
      ['04','Verify','Re-scan remediation and record whether the same issue remains.',GitCompareArrows]
    ].map(([n,t,d,I]:any)=><div className="workflowCard" key={t}><span>{n}</span><I/><h3>{t}</h3><p>{d}</p></div>)}</div></section>
    <section className="publicSection tinted"><SectionHead eyebrow="SECURITY OPERATIONS" title="Built for the workflows teams actually repeat." text="Portfolio views reduce the need to open individual scans just to understand current risk."/><div className="featureGrid">{[
      ['Portfolio issue inbox','Persistent issues across targets with lifecycle state, assignment, due dates and remediation verification.',TriangleAlert],
      ['Asset inventory & drift','Latest discovered assets with status, metadata, provenance and added/removed/changed baselines.',Globe2],
      ['Project scan policies','Reusable scope, depth, pacing, include/exclude patterns and per-check controls.',ServerCog],
      ['Evidence-rich scan history','Score, checks, assets, standards mapping, scan diff and ZAP comparison stay linked.',History],
      ['Workspace governance','Role-based access, invitations, sessions, MFA, API keys, audit events and quotas.',Users],
      ['System operations','Worker health, persistent queue, backups, retention, security events and platform controls.',Activity]
    ].map(([t,d,I]:any)=><article className="featureCard" key={t}><div className="featureIcon"><I/></div><h3>{t}</h3><p>{d}</p><a href="/features">See capability <ChevronRight/></a></article>)}</div></section>
    <section className="publicSection"><div className="splitStory"><div><SectionHead eyebrow="EXPLAINABLE BY DESIGN" title="A finding should tell you what happened, why it matters and what to do next." text="Each result carries evidence, severity, confidence, standards references, remediation and historical lifecycle context."/>
<a className="publicSecondary" href="/standards">View standards approach</a></div><div className="findingMock"><div className="mockTop"><span className="severity high">HIGH</span><span>OPEN · 4 occurrences</span></div><h3>HTTP Strict Transport Security</h3><p className="mockUrl">https://app.example.test/account</p><div className="mockEvidence"><small>EVIDENCE</small><code>Strict-Transport-Security: not present</code></div><div className="mockColumns"><div><small>OWNER</small><b>Application Security</b></div><div><small>DUE</small><b>12 Nov</b></div><div><small>STANDARD</small><b>OWASP ASVS V9</b></div></div><button>Verify remediation</button></div></div></section>
    <section className="publicCTA"><div><span>READY TO ESTABLISH A BASELINE?</span><h2>Start with an authorised target. Keep every decision attached to evidence.</h2></div><a className="publicPrimary large" href="/signup">Create workspace <ArrowRight/></a></section>
  </main>
}

function ProductPreview(){
  return <div className="productPreview"><div className="previewChrome"><i/><i/><i/><span>sentinelscope / production</span></div><div className="previewBody"><aside><div className="previewLogo"><ShieldCheck/></div>{[Activity,FolderKanban,Globe2,TriangleAlert,FileText].map((I:any,i)=><span className={i===0?'on':''} key={i}><I/></span>)}</aside><div className="previewMain"><div className="previewHeader"><div><small>SECURITY OVERVIEW</small><b>Production estate</b></div><span><Search/> Search</span></div><div className="previewHero"><div><small>POSTURE</small><strong>82<em>/100</em></strong><p>4 priority actions need review</p></div><div className="miniBars"><i/><i/><i/><i/></div></div><div className="previewStats"><div><span>Open issues</span><b>18</b></div><div><span>Assets</span><b>147</b></div><div><span>Targets</span><b>8</b></div></div><div className="previewPanel"><div className="previewPanelHead"><b>Priority security actions</b><span>View all</span></div>{[['HIGH','HSTS missing on authenticated route','Customer portal'],['MEDIUM','CSP allows unsafe-inline','Marketing site'],['LOW','Technology banner disclosed','API gateway']].map(([s,t,d])=><div className="previewIssue" key={t}><span className={'severity '+s.toLowerCase()}>{s}</span><div><b>{t}</b><small>{d}</small></div><ChevronRight/></div>)}</div></div></div></div>
}

function StaticPage({page}:{page:string}){
  const pages:any={
    product:{eyebrow:'PLATFORM',title:'One workflow from authorised target to verified remediation.',intro:'SentinelScope combines asset discovery, bounded web assessment, issue lifecycle management, reporting and operational governance in a single security workspace.',sections:[
      ['Assess with policy, not guesswork','Project policies control crawl depth, page limits, request pacing, path scope and individual checks. Every scan keeps the policy snapshot used to produce its evidence.',Radar],
      ['Manage findings beyond one scan','Stable fingerprints create a continuing finding record with owner, due date, status, risk reason, comments, occurrence count and detection history.',Workflow],
      ['Understand your web estate','The asset inventory shows the latest discovered surface for every target and highlights drift between completed scans.',Globe2],
      ['Operate the platform','Persistent jobs, worker heartbeat, schedules, backups, audit events, quotas, retention and system administration support repeatable operation.',ServerCog]
    ]},
    features:{eyebrow:'CAPABILITIES',title:'Depth across identity, scanning, remediation and operations.',intro:'The platform is designed as a connected system: controls are enforced by the API and important state is persisted rather than living only in the browser.',sections:[
      ['Identity & access','HttpOnly sessions, CSRF, login throttling, email verification, password reset, TOTP MFA, session revocation, workspaces and Owner/Admin/Analyst/Viewer permissions.',LockKeyhole],
      ['Target governance','Explicit authorisation acknowledgement plus DNS TXT or well-known-file ownership verification for verified assessment workflows.',ShieldCheck],
      ['Assessment engine','TLS, headers, CSP/HSTS quality, cookies, CORS behaviour, forms, mixed content, methods, disclosure, security.txt and bounded same-origin discovery.',Radar],
      ['Evidence & reporting','Severity, confidence, evidence, impact, remediation, standards mapping, PDF/HTML/JSON reports and ZAP comparison.',FileText],
      ['Automation','Persistent SQLite queue, separate worker, SSE live progress, recurring scans, scoped expiring API keys and machine-readable exports.',Braces],
      ['Security operations','Global issue inbox, asset inventory, lifecycle triage, remediation verification, audit trail, notifications and system-admin controls.',Activity]
    ]},
    security:{eyebrow:'SECURITY MODEL',title:'Safe-by-default behaviour is part of the product boundary.',intro:'SentinelScope is intended for authorised, non-destructive assessment. The scanner constrains what it can reach and what it will do.',sections:[
      ['SSRF and scope controls','URL validation blocks loopback, private, link-local, reserved and metadata destinations by default; redirect destinations are revalidated and crawling remains same-origin.',ShieldCheck],
      ['Bounded execution','Profiles and policies cap pages, depth, response size, pacing and request duration. The product intentionally excludes destructive exploitation and denial-of-service behaviour.',Activity],
      ['Identity protections','Cookie sessions, CSRF validation, password hashing, MFA, login throttling, API-key hashing and scoped bearer permissions protect the management plane.',LockKeyhole],
      ['Auditable administration','System-admin access is separate from workspace administration, and privileged actions are represented in audit data.',History]
    ]},
    standards:{eyebrow:'STANDARDS MAPPING',title:'Evidence is mapped to controls—never presented as blanket compliance.',intro:'Automated checks can support standards-oriented review, but they cannot prove complete application security. SentinelScope keeps mappings at finding/check level and exposes limitations.',sections:[
      ['OWASP Web Security Testing Guide','Transport, configuration, session, client-side and information-disclosure checks reference relevant WSTG areas where appropriate.',BookOpen],
      ['OWASP Application Security Verification Standard','Security controls such as authentication-adjacent browser protections, session cookie attributes and transport configuration can be linked to ASVS areas.',ShieldCheck],
      ['Standards coverage summaries','Completed scans aggregate mapped checks and PASS/WARNING/FAIL/ERROR counts so reviewers can see evidence distribution without misrepresenting certification.',FileText],
      ['Manual assessment remains necessary','Business logic, complex authorization, human process, architecture and source-only weaknesses require manual review beyond a lightweight automated scanner.',Users]
    ]},
    docs:{eyebrow:'DOCUMENTATION',title:'Understand how the platform behaves before you run it.',intro:'The repository includes architecture, API, scanner-check, deployment, security, testing and evaluation documentation. The product UI also keeps methodology visible next to evidence.',sections:[
      ['Start a workspace','Create an account, verify your email, create a project, add an authorised target and choose verification when needed for lab workflows.',FolderKanban],
      ['Define assessment policy','Set crawl limits, scope patterns, pacing and disabled checks at project level. Scan records retain a snapshot.',ServerCog],
      ['Run and observe','Queue a scan, watch progress via server-sent events, then review findings, discovered assets, standards mapping and historical comparisons.',Radar],
      ['Close the loop','Assign findings, add investigation notes, record risk decisions and request remediation verification after a fix is deployed.',CheckCircle2]
    ]},
    solutions:{eyebrow:'SOLUTIONS',title:'A practical security workspace for teams that need evidence, not scanner noise.',intro:'SentinelScope connects repeatable assessment with ownership and remediation. The same platform adapts to coursework, small security teams and governed internal assessment without turning into an exploitation framework.',sections:[
      ['Application security teams','Manage a portfolio issue inbox, target criticality, SLA due dates, assignments, risk decisions and verification runs from one workspace.',TriangleAlert],
      ['Engineering teams','Give developers evidence, remediation guidance, standards context and a clear verification loop instead of detached scanner output.',Workflow],
      ['Security education & research','Use controlled secure/insecure targets, repeatable policies, ZAP comparison and recorded evidence for transparent evaluation.',BookOpen],
      ['Small organisations','Establish an authorised baseline, schedule recurring checks and preserve audit-ready history without a large security stack.',ShieldCheck]
    ]},
    enterprise:{eyebrow:'ENTERPRISE WORKFLOWS',title:'Govern security work across people, targets, evidence and time.',intro:'Enterprise depth comes from controlled transitions and durable evidence: who can act, what changed, when it is due, why a risk was accepted and whether remediation was independently re-checked.',sections:[
      ['Governed issue operations','Saved and shared issue views, severity-based remediation SLAs, bulk triage, assignees, due dates, decision rationale, risk review expiry and immutable activity history.',Users],
      ['Workspace & platform separation','Owner/Admin/Analyst/Viewer workspace permissions remain separate from system-administrator privileges and platform operations.',LockKeyhole],
      ['Operational resilience','Persistent SQLite queue, worker heartbeat, stale-job recovery, backups, retention, quotas, recurring assessment history and cancellation/rerun controls.',ServerCog],
      ['Audit-ready evidence','Findings, scan-policy snapshots, asset drift, standards mappings, comments, verification history and administrative actions remain attached to the workflow.',History]
    ]},
    workflow:{eyebrow:'HOW IT WORKS',title:'From authorised scope to verified remediation in one continuous loop.',intro:'The product is organised around the work security teams repeat: establish scope, discover assets, assess safely, prioritise risk, coordinate remediation and prove the fix.',sections:[
      ['1. Establish scope','Create a project, classify target criticality/environment, acknowledge authorisation and complete ownership verification when the Lab profile requires it.',FolderKanban],
      ['2. Discover & assess','Apply a bounded scan policy, crawl same-origin assets, capture response evidence and run non-destructive transport/browser/configuration checks.',Radar],
      ['3. Prioritise & assign','Use effective severity, business criticality, recurrence and SLA state to rank issues; assign owners and record investigation context.',TriangleAlert],
      ['4. Verify & govern','Queue remediation verification, compare stable fingerprints, track asset drift, retain reports and use audit/activity evidence for accountability.',CheckCircle2]
    ]},
    research:{eyebrow:'RESEARCH & EVALUATION',title:'Designed so scanner claims can be measured instead of assumed.',intro:'SentinelScope supports a dissertation-style evaluation model with controlled targets, planted weaknesses, repeatable scan policies and a comparable external baseline.',sections:[
      ['Controlled test environments','Secure and intentionally insecure demonstration sites let checks be evaluated without testing unrelated third-party systems.',ShieldCheck],
      ['Detection metrics','Track planted vulnerability detection, false positives, duration, page coverage and remediation-verification outcomes.',Activity],
      ['OWASP ZAP comparison','Import ZAP JSON and preserve overlap, scanner-only and ZAP-only evidence alongside the SentinelScope scan.',GitCompareArrows],
      ['Explicit limitations','Automated checks do not claim to solve business logic, complex authorization, human process, source-only weaknesses or complete compliance.',BookOpen]
    ]},
    'responsible-use':{eyebrow:'RESPONSIBLE USE',title:'Authorisation and bounded behaviour are product requirements, not a disclaimer.',intro:'The scanner is built for systems you own or have explicit permission to assess. Safety controls remain active even for advanced workflows.',sections:[
      ['Authorisation first','Targets require an explicit permission acknowledgement; advanced Lab workflows require stronger target verification.',ShieldCheck],
      ['Network safety','Private, loopback, link-local, reserved and metadata destinations are blocked by default and redirect destinations are revalidated.',Globe2],
      ['Non-destructive checks','The platform avoids brute force, credential theft, persistence, destructive modification, unrestricted exploitation and denial-of-service testing.',LockKeyhole],
      ['Evidence over exploitation','Checks gather bounded HTTP/TLS/configuration evidence and explain remediation rather than attempting to weaponize findings.',FileText]
    ]},
    deployment:{eyebrow:'DEPLOYMENT MODEL',title:'A production-style single-node architecture with explicit operational boundaries.',intro:'The current product intentionally uses SQLite WAL while separating API, worker and reverse-proxy responsibilities. It is suitable for this academic/product scope without pretending to be a multi-region distributed control plane.',sections:[
      ['Web & API tier','React/Vite serves the responsive interface while Flask exposes versioned APIs behind a reverse proxy with secure cookie and CSRF controls.',Braces],
      ['Worker isolation','Persistent queued scan jobs execute in a separate worker process with heartbeat, retries, cancellation and stale-lease recovery.',ServerCog],
      ['Durable local state','SQLite WAL stores workspace state, evidence, queue data, audit records and lifecycle history; online backups and integrity-aware restore are supported.',Database],
      ['Scaling boundary','For horizontally distributed or multi-region operation, the documented architecture expects database/queue/object-storage components to be replaced without changing the product workflow model.',Activity]
    ]},
    trust:{eyebrow:'TRUST CENTER',title:'Security boundaries, operational controls and evidence you can inspect.',intro:'SentinelScope is designed so security teams can understand not only what the product finds, but how the platform itself is controlled, audited and operated.',sections:[
      ['Identity assurance','Email verification, login throttling, HttpOnly sessions, CSRF protection, TOTP MFA, one-time recovery codes, session revocation and role-aware workspace access.',LockKeyhole],
      ['Data & secret handling','SQLite WAL persistence, hashed API/session tokens, optional Fernet encryption for protected secrets, integrity-aware backups and explicit retention controls.',Database],
      ['Scanner safety boundary','SSRF-resistant target validation, same-origin crawling, bounded requests, public-destination validation and an explicit exclusion of destructive exploitation, brute force and denial-of-service behavior.',ShieldCheck],
      ['Auditability','Administrative actions, issue decisions, assignment changes, scan policy snapshots, delivery attempts and remediation history remain linked to actors and timestamps.',History]
    ]},
    integrations:{eyebrow:'INTEGRATIONS',title:'Connect security events to the systems your team already operates.',intro:'Signed outbound webhooks and scoped API keys let SentinelScope participate in ticketing, chat, SIEM and internal automation without turning the scanner into an uncontrolled integration hub.',sections:[
      ['Signed webhooks','Subscribe HTTPS endpoints to scan, finding, risk and schedule events. Every request carries event, delivery ID and HMAC-SHA256 signature metadata.',Webhook],
      ['Durable delivery history','Deliveries are queued, attempted by workers, persisted with response metadata and retryable from the workspace UI.',Activity],
      ['Scoped API access','Expiring bearer keys expose read, scan and write capabilities with server-side scope enforcement and one-time raw secret display.',KeyRound],
      ['Operational control','Pause endpoints, rotate signing secrets, send test events, review failures and explicitly retry delivery attempts.',ServerCog]
    ]},
    api:{eyebrow:'DEVELOPER API',title:'Automate assessments and security operations through explicit, scoped interfaces.',intro:'The REST API mirrors core workspace workflows so integrations can create projects and targets, queue scans, inspect findings, manage lifecycle state and retrieve reports without bypassing governance.',sections:[
      ['Authentication','Interactive sessions use CSRF-protected cookies; automation uses expiring scoped bearer keys whose stored representation is hashed.',KeyRound],
      ['Assessment operations','Queue authorised scans, retrieve live state, consume findings/assets/standards summaries and export JSON/HTML/PDF evidence.',Radar],
      ['Lifecycle operations','Manage persistent issue state, comments, assignment, due dates and remediation verification through workspace-authorised endpoints.',Workflow],
      ['Administrative boundaries','Role checks, API scopes, verified-target rules, project archive state and system-admin boundaries are enforced by the backend.',ShieldCheck]
    ]},
    architecture:{eyebrow:'ARCHITECTURE',title:'A modular single-node architecture with explicit boundaries for future scale.',intro:'The current product intentionally uses SQLite WAL for its deployment scope while preserving clear API, worker, scanner and persistence boundaries that can be replaced independently later.',sections:[
      ['React product shell','A responsive TypeScript application provides separate desktop and mobile interaction models, command navigation and persistent workflow views.',Braces],
      ['Flask application API','Authentication, RBAC, governance, reports, integrations and security workflow APIs remain separated from scanner execution.',ServerCog],
      ['Persistent worker queue','Scans and webhook deliveries are processed through durable SQLite jobs with retries, cancellation, stale-job recovery and worker heartbeats.',Activity],
      ['Scanner isolation boundary','Target validation, safe HTTP client behavior, crawler scope and check execution are encapsulated from account and administration logic.',ShieldCheck]
    ]},
    'scanner-checks':{eyebrow:'SCANNER CHECK CATALOG',title:'Transparent checks with evidence, confidence and bounded behavior.',intro:'SentinelScope favors repeatable, explainable observations over opaque vulnerability claims. Each check records what was observed and how the result should be reviewed.',sections:[
      ['Transport & TLS','HTTPS, redirects, certificate validation, protocol/cipher evidence, expiry and HSTS presence/quality.',LockKeyhole],
      ['Browser controls','CSP presence and directive quality, frame protection, MIME sniffing, referrer policy, permissions policy and cross-origin isolation signals.',ShieldCheck],
      ['Cookies, forms & CORS','Cookie flags, form transport, CSRF heuristics, sensitive GET forms, cross-origin form actions and benign Origin-reflection behavior.',Braces],
      ['Disclosure & governance','Technology banners, developer markers, mixed content, advertised methods, security.txt and asset-level response metadata.',Search]
    ]},
    reports:{eyebrow:'REPORTING',title:'Reports that preserve the context needed to make a decision.',intro:'Exports are generated from persisted scan evidence rather than from a disconnected browser snapshot, so policy, scope, target context and limitations travel with the result.',sections:[
      ['Executive context','Security score, target identity, business context, active risk and priority findings are summarized for non-specialist review.',FileText],
      ['Technical evidence','Detailed findings include evidence, confidence, standards references, remediation and affected URLs.',Search],
      ['Scope & methodology','Report outputs retain scan profile, policy snapshot, assets, drift, methodology and scanner limitations.',Radar],
      ['Portable formats','PDF supports stakeholder distribution; HTML supports browser review; JSON supports downstream automation and archival.',Braces]
    ]},
    developers:{eyebrow:'DEVELOPERS',title:'Build controlled automation around the same workflows the UI uses.',intro:'Developer-facing capabilities are intentionally connected to the platform permission model: automation can accelerate work, but it cannot silently bypass authorisation or scanner safety controls.',sections:[
      ['REST API','Workspace operations are available through versioned API endpoints with cookie-session or bearer-key authentication.',Braces],
      ['Webhooks','Subscribe to high-value events and verify each delivery with HMAC-SHA256 using a workspace-managed signing secret.',Webhook],
      ['Evidence exports','Consume report JSON, issue portfolios, asset inventories, audit records and scan histories for approved internal workflows.',FileText],
      ['Repository documentation','Architecture, deployment, API, scanner-check, ethics and evaluation documents explain implementation choices and current scaling boundaries.',BookOpen]
    ]},
    about:{eyebrow:'ABOUT THE PROJECT',title:'A transparent security-assessment platform built for explainability.',intro:'SentinelScope focuses on clear methodology, reproducible evidence and safe operation rather than opaque “magic” vulnerability claims.',sections:[
      ['Purpose','Help students, small teams and security practitioners understand repeatable web-security checks and track remediation in a controlled workflow.',ShieldCheck],
      ['Architecture','React + TypeScript frontend, Flask API, SQLite WAL persistence, separate worker process and Docker/Nginx deployment option.',Database],
      ['Evaluation mindset','Controlled secure/insecure demonstration targets, regression tests, browser E2E and optional OWASP ZAP result comparison support measurable evaluation.',GitCompareArrows],
      ['Responsible use','Only assess systems you own or are explicitly authorised to test. The scanner is designed to remain non-destructive.',LockKeyhole]
    ]}
  };
  const p=pages[page]||pages.product;
  return <main><section className="pageHero"><div><span>{p.eyebrow}</span><h1>{p.title}</h1><p>{p.intro}</p><div className="heroCtas"><a className="publicPrimary large" href="/signup">Create workspace <ArrowRight/></a><a className="publicSecondary" href="/login">Sign in</a></div></div></section><section className="publicSection"><div className="detailGrid">{p.sections.map(([t,d,I]:any)=><article key={t}><I/><h2>{t}</h2><p>{d}</p></article>)}</div></section><section className="publicCTA"><div><span>AUTHORISATION FIRST</span><h2>Security tooling is useful only when the evidence and boundaries are clear.</h2></div><a className="publicPrimary large" href="/security">Read the security model <ArrowRight/></a></section></main>
}

function SectionHead({eyebrow,title,text}:any){return <div className="sectionHead"><span>{eyebrow}</span><h2>{title}</h2><p>{text}</p></div>}

function StatusPage(){
  const[health,setHealth]=useState<any>(null),[error,setError]=useState('');
  useEffect(()=>{let live=true;const check=async()=>{try{const r=await fetch('/health',{cache:'no-store'});const d=await r.json();if(!r.ok)throw new Error('Health endpoint returned '+r.status);if(live){setHealth(d);setError('')}}catch(e:any){if(live)setError(e.message||'Service health could not be checked')}};check();const id=setInterval(check,30000);return()=>{live=false;clearInterval(id)}},[]);
  const ok=health?.status==='ok'&&!error;
  return <main><section className="pageHero statusHero"><div><span>PLATFORM STATUS</span><h1>Operational transparency without exposing sensitive telemetry.</h1><p>This page reads SentinelScope's public-safe health endpoint. Administrative metrics, worker internals, security events and queue details remain authenticated.</p></div></section>
  <section className="publicSection"><div className={'statusBanner '+(ok?'operational':error?'degraded':'checking')}><span className="statusPulse"/><div><b>{ok?'All public platform checks operational':error?'Service health check unavailable':'Checking platform health…'}</b><p>{ok?'API health is responding normally.':error?error:'Waiting for the public health endpoint.'}</p></div><small>{new Date().toLocaleString()}</small></div>
  <div className="statusComponents">{[['API service',health?.status==='ok'],['Persistence layer',health?.database==='sqlite'],['Worker queue',health?.queue==='sqlite-worker']].map(([name,state]:any)=><article key={name}><div><b>{name}</b><small>Public-safe component signal</small></div><span className={'componentState '+(state?'good':'unknown')}>{state?'OPERATIONAL':'CHECKING'}</span></article>)}</div>
  <div className="statusTrust"><ShieldCheck/><div><h2>Why this page is intentionally minimal</h2><p>Detailed worker heartbeats, job failures, audit logs, security events, database sizes and operational controls belong in the authenticated System Admin console. The public status view exposes only the information necessary to confirm basic service availability.</p></div></div></section></main>
}
