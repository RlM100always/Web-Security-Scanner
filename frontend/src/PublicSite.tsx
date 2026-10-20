import React,{useState}from'react';
import{ShieldCheck,Menu,X,ArrowRight,CheckCircle2,Radar,FolderKanban,TriangleAlert,History,KeyRound,Database,Users,FileText,Globe2,LockKeyhole,Workflow,Search,Activity,Braces,BookOpen,ChevronRight,ServerCog,GitCompareArrows}from'lucide-react';
import'./public.css';

const links=[['Product','/product'],['Features','/features'],['Security','/security'],['Standards','/standards'],['Docs','/docs'],['About','/about']];

export default function PublicSite({path='/'}:{path?:string}){
  const[open,setOpen]=useState(false);
  const page=path.replace(/^\//,'')||'home';
  return <div className="publicSite">
    <header className="publicNav">
      <a className="publicBrand" href="/"><span><ShieldCheck/></span><div><b>SentinelScope</b><small>Web Security Assessment Platform</small></div></a>
      <nav className={open?'open':''}>{links.map(([n,h])=><a key={h} className={path===h?'active':''} href={h}>{n}</a>)}</nav>
      <div className="publicActions"><a className="textLink" href="/login">Sign in</a><a className="publicPrimary" href="/signup">Start workspace <ArrowRight/></a><button className="publicMenu" onClick={()=>setOpen(!open)} aria-label="Toggle navigation">{open?<X/>:<Menu/>}</button></div>
    </header>
    {page==='home'?<Home/>:<StaticPage page={page}/>}
    <footer className="publicFooter"><div><a className="publicBrand" href="/"><span><ShieldCheck/></span><div><b>SentinelScope</b><small>Authorised, non-destructive assessment</small></div></a><p>Designed for explainable web-security assessment, remediation tracking and repeatable evidence.</p></div><div className="footerGrid"><div><b>Platform</b><a href="/product">Product</a><a href="/features">Features</a><a href="/standards">Standards</a></div><div><b>Trust</b><a href="/security">Security model</a><a href="/docs">Documentation</a><a href="/about">About</a></div><div><b>Workspace</b><a href="/login">Sign in</a><a href="/signup">Create account</a></div></div><small className="footerNote">Use only against systems you own or are explicitly authorised to assess. SentinelScope intentionally avoids destructive exploitation, credential attacks and denial-of-service behaviour.</small></footer>
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
