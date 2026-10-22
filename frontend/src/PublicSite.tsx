import React,{useEffect,useState}from'react';
import{ShieldCheck,Menu,X,ArrowRight,CheckCircle2,LayoutDashboard,Radar,FolderKanban,TriangleAlert,History,KeyRound,Database,Users,FileText,Globe2,LockKeyhole,Workflow,Search,Activity,Braces,BookOpen,ChevronRight,MessageSquare,ServerCog,GitCompareArrows,Webhook,CalendarClock,SlidersHorizontal,Network}from'lucide-react';
import'./public.css';import'./public-enterprise.css';

const links=[['Product','/product'],['Features','/features'],['Solutions','/solutions'],['Enterprise','/enterprise'],['Developers','/developers'],['Docs','/docs']];

export default function PublicSite({path='/'}:{path?:string}){
  const[open,setOpen]=useState(false);
  const page=path.replace(/^\//,'')||'home';
  useEffect(()=>{setOpen(false)},[path]);
  useEffect(()=>{if(!open)return;const onKey=(event:KeyboardEvent)=>{if(event.key==='Escape'){setOpen(false);document.querySelector<HTMLButtonElement>('.publicMenu')?.focus()}};window.addEventListener('keydown',onKey);return()=>window.removeEventListener('keydown',onKey)},[open]);
  useEffect(()=>{const meta:any={
    home:['SentinelScope — Web Security Assessment Platform','Authorised web-security assessment, asset context, persistent issue management and remediation verification.'],
    product:['Product | SentinelScope','Explore governed scanning, asset inventory, vulnerability management, reporting and platform operations.'],
    enterprise:['Enterprise Security Workflows | SentinelScope','Workspace governance, auditability, access reviews, automation, queue operations, backups and retention.'],
    security:['Security Model | SentinelScope','Understand SentinelScope target authorisation, SSRF protections, account security and non-destructive scanner boundaries.'],
    standards:['Standards Mapping | SentinelScope','See how SentinelScope maps evidence to relevant OWASP WSTG and OWASP ASVS references without claiming blanket compliance.'],
    developers:['Developers | SentinelScope','Use scoped API keys, signed webhooks and evidence exports to automate approved SentinelScope workflows.'],
    'exposure-management':['Exposure Management | SentinelScope','Connect governed projects, authorised targets, discovered assets, persistent security issues and accountable owners.'],
    'asset-inventory':['Asset Inventory | SentinelScope','Review bounded scanner-discovered assets, business context, provenance and baseline drift.'],
    'vulnerability-management':['Vulnerability Management | SentinelScope','Prioritise persistent issues, assign ownership, manage risk decisions and verify remediation.'],
    reports:['Security Reporting | SentinelScope','Generate evidence-rich PDF, HTML and JSON assessment reports with export provenance.'],
    status:['Platform Status | SentinelScope','Public-safe SentinelScope service availability without exposing sensitive operational telemetry.'],
    '404':['Page not found | SentinelScope','The requested SentinelScope page could not be found.']
  };const m=meta[page]||['SentinelScope — '+page.replaceAll('-',' '),'SentinelScope authorised, evidence-first web security assessment platform.'];document.title=m[0];let tag=document.querySelector('meta[name="description"]');if(!tag){tag=document.createElement('meta');tag.setAttribute('name','description');document.head.appendChild(tag)}tag.setAttribute('content',m[1])},[page]);
  return <div className="publicSite">
    <a className="skipLink" href="#main-content" onClick={event=>{event.preventDefault();document.getElementById("main-content")?.focus()}}>Skip to main content</a>
    <header className="publicNav">
      <a className="publicBrand" href="/"><span><ShieldCheck/></span><div><b>SentinelScope</b><small>Web Security Assessment Platform</small></div></a>
      <nav id="public-primary-nav" aria-label="Primary navigation" className={open?'open':''}>{links.map(([n,h])=><a key={h} className={path===h?'active':''} href={h} onClick={()=>setOpen(false)}>{n}</a>)}</nav>
      <div className="publicActions"><a className="textLink" href="/login">Sign in</a><a className="publicPrimary" href="/signup">Start workspace <ArrowRight/></a><button className="publicMenu" onClick={()=>setOpen(!open)} aria-label="Toggle navigation" aria-controls="public-primary-nav" aria-expanded={open}>{open?<X/>:<Menu/>}</button></div>
    </header>
    <div className="publicProofBar"><span><ShieldCheck/> Authorised assessment only</span><a href="/status">Live platform status</a><a href="/trust">Trust & governance</a><a href="/security">Security model</a></div>
    <div id="main-content" tabIndex={-1}>{page==='home'?<Home/>:page==='status'?<StatusPage/>:<StaticPage page={page}/>}</div>
    <footer className="publicFooter"><div><a className="publicBrand" href="/"><span><ShieldCheck/></span><div><b>SentinelScope</b><small>Authorised, non-destructive assessment</small></div></a><p>Designed for explainable web-security assessment, remediation tracking and repeatable evidence.</p></div><div className="footerGrid"><div><b>Platform</b><a href="/product">Product</a><a href="/exposure-management">Exposure management</a><a href="/asset-inventory">Asset inventory</a><a href="/scan-profiles">Scan profiles</a><a href="/vulnerability-management">Issue management</a><a href="/continuous-monitoring">Continuous monitoring</a></div><div><b>Enterprise</b><a href="/enterprise">Enterprise controls</a><a href="/governance">Governance</a><a href="/integrations">Integrations</a><a href="/reports">Reporting</a><a href="/deployment">Deployment model</a></div><div><b>Learn</b><a href="/getting-started">Getting started</a><a href="/workflow">Workflow</a><a href="/methodology">Methodology</a><a href="/standards">Standards</a><a href="/research">Research</a></div><div><b>Developers</b><a href="/developers">Developer platform</a><a href="/api">API access</a><a href="/architecture">Architecture</a><a href="/scanner-checks">Scanner checks</a></div><div><b>Trust</b><a href="/trust">Trust center</a><a href="/status">Platform status</a><a href="/security">Security model</a><a href="/responsible-use">Responsible use</a><a href="/standards">Standards</a></div><div><b>Workspace</b><a href="/login">Sign in</a><a href="/signup">Create account</a></div></div><small className="footerNote">Use only against systems you own or are explicitly authorised to assess. SentinelScope intentionally avoids destructive exploitation, credential attacks and denial-of-service behaviour.</small></footer>
  </div>
}

function Home(){
  return <main>
    <section className="publicHero redesignedHero">
      <div className="heroAtmosphere" aria-hidden="true"><i/><i/><i/><span className="heroOrbit heroOrbitOne"/><span className="heroOrbit heroOrbitTwo"/></div>
      <div className="heroCopy redesignedHeroCopy">
        <div className="heroKicker"><span></span> EVIDENCE-FIRST APPLICATION SECURITY</div>
        <h1>Turn web-security checks into a <em>managed remediation workflow.</em></h1>
        <p>Discover web assets, run bounded authorised assessments, prioritise findings, assign remediation, verify fixes and preserve standards-mapped evidence — all from one workspace.</p>
        <div className="heroCtas"><a className="publicPrimary large" href="/signup">Start workspace <ArrowRight/></a><a className="publicSecondary" href="/product"><MessageSquare/> Explore the platform</a></div>
        <div className="heroHighlights" aria-label="Core workflow">
          <article><span><Search/></span><div><b>Discover & scan</b><small>Find and assess web assets</small></div></article>
          <article><span><ShieldCheck/></span><div><b>Prioritise findings</b><small>Focus on what matters</small></div></article>
          <article><span><Activity/></span><div><b>Track remediation</b><small>Verify fixes and preserve evidence</small></div></article>
        </div>
        <div className="heroTrust redesignedHeroTrust">
          <span><ShieldCheck/><b>Authorised</b><small>assessments only</small></span>
          <span><FileText/><b>Evidence-first</b><small>standards-mapped</small></span>
          <span><Users/><b>Team-ready</b><small>remediation tracking</small></span>
          <span><CheckCircle2/><b>Audit-friendly</b><small>repeatable evidence</small></span>
        </div>
      </div>
      <div className="heroVisual">
        <div className="heroVisualGlow" aria-hidden="true"/>
        <div className="heroFloatingCard floatingFindings"><span className="floatIcon danger"><TriangleAlert/></span><div><small>OPEN FINDINGS</small><b>18</b><em><Activity/> −12% this month</em></div><div className="sparkline sparkRed"><i/><i/><i/><i/><i/><i/><i/></div></div>
        <ProductPreview/>
        <div className="heroFloatingCard floatingSla"><span className="floatIcon success"><CheckCircle2/></span><div><small>REMEDIATION SLA</small><b>92<small>%</small></b><em>Met last 30 days</em></div><div className="sparkline sparkGreen"><i/><i/><i/><i/><i/><i/><i/></div></div>
        <div className="heroFloatingCard floatingVerification"><span className="floatIcon violet"><Activity/></span><div><small>VERIFICATION RATE</small><b>87<small>%</small></b><em>Fixes re-checked</em></div></div>
        <div className="heroStandards"><ShieldCheck/><span><b>Standards aligned</b><small>OWASP · NIST · ISO 27001</small></span><ChevronRight/></div>
      </div>
    </section>
    <section className="logoStrip"><span>BUILT AROUND</span><b>OWASP WSTG</b><b>OWASP ASVS</b><b>Evidence-led findings</b><b>Persistent assessment history</b><b>Mobile-ready workspace</b></section>
    <section className="publicSection homeWhatSection">
      <div className="homeWhatHeader"><SectionHead eyebrow="WHAT SENTINELSCOPE DOES" title="A security assessment becomes useful when someone can act on it." text="SentinelScope connects authorised scope, repeatable checks, evidence, accountable ownership and a fresh verification run. It is built to make the work after a scan as clear as the scan itself."/><div className="homeWhatCallout"><span><ShieldCheck/></span><div><b>Built around authorised assessment</b><p>Only assess systems you own or have explicit permission to test. The visual data below is illustrative, not live customer telemetry.</p></div></div></div>
      <div className="homeModuleGrid">
        <article className="homeModuleCard"><div className="homeModuleCopy"><span className="homeModuleIndex">01 / SCOPE</span><div className="homeModuleIcon"><Globe2/></div><h3>Know what is in scope.</h3><p>Group approved targets into projects, attach environment and criticality, and keep discovered same-origin assets linked to the assessment that found them.</p><a href="/asset-inventory">Explore asset inventory <ArrowRight/></a></div><HomeModulePreview kind="scope"/></article>
        <article className="homeModuleCard"><div className="homeModuleCopy"><span className="homeModuleIndex">02 / PRIORITISE</span><div className="homeModuleIcon"><TriangleAlert/></div><h3>Turn signals into owned issues.</h3><p>Keep evidence, confidence, remediation guidance, severity, owner, due date and decision history together as repeat scans update the same finding record.</p><a href="/vulnerability-management">Explore issue management <ArrowRight/></a></div><HomeModulePreview kind="findings"/></article>
        <article className="homeModuleCard"><div className="homeModuleCopy"><span className="homeModuleIndex">03 / VERIFY</span><div className="homeModuleIcon"><GitCompareArrows/></div><h3>Prove the fix with new evidence.</h3><p>Run a fresh bounded assessment after a change, compare the result with the original finding, and keep the verification outcome and audit history attached.</p><a href="/workflow">Explore the lifecycle <ArrowRight/></a></div><HomeModulePreview kind="verification"/></article>
      </div>
    </section>
    <section className="publicSection"><SectionHead eyebrow="OPERATING MODEL" title="Security work should move, not sit in a report." text="SentinelScope connects discovery, assessment, triage and verification so every finding has context, ownership and a next action."/><div className="workflowRail">{[
      ['01','Discover','Build a persistent inventory of in-scope pages and response metadata.',Globe2],
      ['02','Assess','Run policy-bound, non-destructive checks with evidence and confidence.',Radar],
      ['03','Triage','Assign owners, due dates, state, comments and risk decisions.',TriangleAlert],
      ['04','Verify','Re-scan remediation and record whether the same issue remains.',GitCompareArrows]
    ].map(([n,t,d,I]:any)=><div className="workflowCard" key={t}><span>{n}</span><I/><h3>{t}</h3><p>{d}</p></div>)}</div></section>
    <section className="publicSection tinted"><SectionHead eyebrow="SECURITY OPERATIONS" title="Built for the workflows teams actually repeat." text="Portfolio views reduce the need to open individual scans just to understand current risk."/><div className="featureGrid">{[
      ['Portfolio issue inbox','Persistent issues across targets with lifecycle state, assignment, due dates and remediation verification.',TriangleAlert],
      ['Asset inventory & drift','Latest discovered assets with status, metadata, provenance and added/removed/changed baselines.',Globe2],
      ['Versioned scan profiles','Reusable named configurations standardise scope, depth, pacing and checks across manual and recurring assessments while preserving immutable per-scan provenance.',ServerCog],
      ['Evidence-rich scan history','Score, checks, assets, standards mapping, scan diff and ZAP comparison stay linked.',History],
      ['Workspace governance','Role-based access, invitations, sessions, MFA, API keys, audit events and quotas.',Users],
      ['System operations','Worker health, persistent queue, backups, retention, security events and platform controls.',Activity]
    ].map(([t,d,I]:any)=><article className="featureCard" key={t}><div className="featureIcon"><I/></div><h3>{t}</h3><p>{d}</p><a href="/features">See capability <ChevronRight/></a></article>)}</div></section>
    <section className="publicSection"><div className="splitStory"><div><SectionHead eyebrow="EXPLAINABLE BY DESIGN" title="A finding should tell you what happened, why it matters and what to do next." text="Each result carries evidence, severity, confidence, standards references, remediation and historical lifecycle context."/>
<a className="publicSecondary" href="/standards">View standards approach</a></div><div className="findingMock"><div className="mockTop"><span className="severity high">HIGH</span><span>OPEN · 4 occurrences</span></div><h3>HTTP Strict Transport Security</h3><p className="mockUrl">https://app.example.test/account</p><div className="mockEvidence"><small>EVIDENCE</small><code>Strict-Transport-Security: not present</code></div><div className="mockColumns"><div><small>OWNER</small><b>Application Security</b></div><div><small>DUE</small><b>12 Nov</b></div><div><small>STANDARD</small><b>OWASP ASVS V9</b></div></div><a className="mockAction" href="/vulnerability-management">Explore remediation workflow <ArrowRight/></a></div></div></section>
    <section className="publicSection roleSection"><SectionHead eyebrow="BUILT FOR THE OPERATING TEAM" title="One platform, different jobs to be done." text="Each role gets the context it needs without flattening security work into one generic dashboard."/><div className="roleGrid"><article><div className="featureIcon"><ShieldCheck/></div><span>APPSEC / SECURITY</span><h3>Prioritise risk and govern decisions.</h3><p>Use exposure context, persistent issue state, standards mapping, risk acceptance, audit and remediation verification to run a measurable security programme.</p><a href="/governance">Explore governance <ChevronRight/></a></article><article><div className="featureIcon"><Workflow/></div><span>ENGINEERING</span><h3>Know what to fix and prove it is fixed.</h3><p>Move from evidence to owner, due date, comments and a fresh verification scan without losing the original technical context.</p><a href="/vulnerability-management">Explore issue workflow <ChevronRight/></a></article><article><div className="featureIcon"><Activity/></div><span>PLATFORM / OPERATIONS</span><h3>Keep assessment reliable at scale.</h3><p>Manage reusable scan profiles, recurring schedules, workers, queue health, quotas, integrations, retention and backups.</p><a href="/enterprise">Explore platform operations <ChevronRight/></a></article></div></section>
    <EvidenceLifecycle/>
    <WorkflowCompare variant="home"/>
    <PublicFaq page="home"/>
    <section className="publicCTA"><div><span>READY TO ESTABLISH A BASELINE?</span><h2>Start with an authorised target. Keep every decision attached to evidence.</h2></div><a className="publicPrimary large" href="/signup">Create workspace <ArrowRight/></a></section>
  </main>
}


function HomeModulePreview({kind}:{kind:'scope'|'findings'|'verification'}){
  const data:any={
    scope:{kicker:'TARGET INVENTORY',title:'Approved web estate',status:'IN SCOPE',stats:[['Targets','08'],['Assets','147'],['Drift','02']],rows:[['VERIFIED','Customer portal','Production · owner assigned'],['ACTIVE','Public API','Staging · bounded scope'],['REVIEW','Help centre','New assets detected']]},
    findings:{kicker:'PERSISTENT ISSUE INBOX',title:'Priority remediation',status:'TRIAGE',stats:[['Open','18'],['High','04'],['Assigned','12']],rows:[['HIGH','HSTS missing on route','Evidence attached · owner set'],['MEDIUM','CSP directive review','Due in 2 days'],['IN PROGRESS','Cookie flags corrected','Awaiting re-scan']]},
    verification:{kicker:'REMEDIATION EVIDENCE',title:'Verification history',status:'RE-CHECKED',stats:[['Verified','26'],['Due','03'],['SLA','92%']],rows:[['VERIFIED','Transport header corrected','Fresh scan confirms change'],['IN PROGRESS','CSP policy updated','Verification pending'],['STILL PRESENT','Cookie attribute missing','Keep issue open']]}
  };
  const v=data[kind];
  return <div className={'homeModuleVisual homeModuleVisual-'+kind} aria-label={v.title+' illustrative interface'}>
    <div className="homeModuleVisualTop"><span><i/>{v.kicker}</span><b>ILLUSTRATIVE</b></div>
    <div className="homeModuleMiniToolbar"><div><small>WORKSPACE / SAMPLE</small><strong>{v.title}</strong></div><span>{v.status}</span></div>
    <div className="homeModuleMiniStats">{v.stats.map(([label,value]:string[])=><div key={label}><small>{label}</small><b>{value}</b></div>)}</div>
    <div className="homeModuleMiniRows">{v.rows.map(([status,title,sub]:string[])=><div key={title}><span className={'homeModuleStatus homeModuleStatus-'+status.toLowerCase().replaceAll(' ','-')}>{status}</span><div><b>{title}</b><small>{sub}</small></div><ChevronRight/></div>)}</div>
  </div>
}

function EvidenceLifecycle(){
  const steps:any=[
    {n:'01',title:'Capture',text:'A bounded assessment records the check, URL, response evidence and policy snapshot.',icon:Radar},
    {n:'02',title:'Correlate',text:'A stable fingerprint links repeat detections to one continuing issue record.',icon:Network},
    {n:'03',title:'Assign',text:'An owner, due date and decision rationale make the next action explicit.',icon:Users},
    {n:'04',title:'Remediate',text:'Engineering changes the application and records relevant investigation notes.',icon:Workflow},
    {n:'05',title:'Verify',text:'A fresh assessment records whether the issue is fixed or still present.',icon:CheckCircle2}
  ];
  return <section className="publicSection evidenceLifecycleSection"><div className="evidenceLifecycleIntro"><SectionHead eyebrow="THE FINDING LIFECYCLE" title="From first signal to a verified outcome." text="A scan is a point-in-time observation. The lifecycle makes follow-up visible and preserves why a finding changed state."/></div><div className="evidenceLifecycleRail">{steps.map((s:any,i:number)=><article key={s.n}><span className="evidenceLifecycleNum">{s.n}</span><div className="evidenceLifecycleIcon"><s.icon/></div><h3>{s.title}</h3><p>{s.text}</p>{i<steps.length-1&&<span className="evidenceLifecycleConnector"><ArrowRight/></span>}</article>)}</div><div className="evidenceLifecycleFoot"><ShieldCheck/><p><b>Closure is evidence-led.</b> A status change alone is not proof that a weakness has disappeared. Keep the original observation and the verification result together.</p><a href="/vulnerability-management">See issue lifecycle <ArrowRight/></a></div></section>
}

function WorkflowCompare({variant='home'}:{variant?:string}){
  const copy:any={
    home:{eyebrow:'WHY THE WORKFLOW MATTERS',title:'Replace disconnected scan output with accountable security work.',text:'The difference is not another chart. It is the context and evidence that stay connected after a finding is detected.'},
    product:{eyebrow:'PRODUCT IN PRACTICE',title:'One finding record. A clear next action.',text:'Move from detection to ownership and verification without losing the original evidence or the policy that produced it.'},
    teams:{eyebrow:'TEAM HANDOFF',title:'Give each team the context it needs.',text:'Security can prioritise and govern; engineering can fix; platform teams can keep recurring assessments reliable.'},
    governance:{eyebrow:'GOVERNANCE IN PRACTICE',title:'Make security decisions reviewable later.',text:'Roles, rationale, due dates, exports and activity history keep accountability visible across the issue lifecycle.'},
    automation:{eyebrow:'AUTOMATION WITH GUARDRAILS',title:'Automate repeatable work without bypassing policy.',text:'Scoped credentials and signed events connect approved workflows to the same permission and safety boundaries as the UI.'},
    onboarding:{eyebrow:'GETTING STARTED',title:'Move from an empty workspace to a useful baseline.',text:'A guided sequence keeps account security, authorised scope, assessment policy and evidence review in the right order.'},
    trust:{eyebrow:'TRUST BY DESIGN',title:'Safety controls should be visible before a scan starts.',text:'Explicit authorisation, bounded requests, destination validation and evidence limitations are part of the operating model.'}
  };
  const v=copy[variant]||copy.product;
  return <section className="publicSection workflowCompareSection"><SectionHead eyebrow={v.eyebrow} title={v.title} text={v.text}/><div className="workflowCompareGrid">
    <article className="workflowComparePanel workflowCompareBefore"><div className="workflowCompareLabel"><span>WITHOUT A CONNECTED WORKFLOW</span><span className="workflowCompareIcon"><History/></span></div><h3>Fragmented follow-up</h3><ul><li><X/> Scan results exported and separated from ownership</li><li><X/> Repeat detections create duplicate triage work</li><li><X/> Remediation status depends on manual updates</li><li><X/> Closure is hard to prove from a new observation</li></ul><div className="workflowCompareFoot">Context gets lost between tools.</div></article>
    <div className="workflowCompareBridge" aria-hidden="true"><ArrowRight/></div>
    <article className="workflowComparePanel workflowCompareAfter"><div className="workflowCompareLabel"><span>WITH SENTINELSCOPE</span><span className="workflowCompareIcon"><ShieldCheck/></span></div><h3>Connected, reviewable work</h3><ul><li><CheckCircle2/> Evidence and policy snapshot stay attached</li><li><CheckCircle2/> Stable fingerprints preserve finding history</li><li><CheckCircle2/> Owner, due date and decision are explicit</li><li><CheckCircle2/> A fresh assessment records verification</li></ul><div className="workflowCompareFoot">One record follows the work through its lifecycle.</div></article>
  </div></section>
}

function PublicFaq({page}:{page:string}){
  const group:any={
    home:[
      ['What is SentinelScope?','A workspace for authorised, bounded web-security assessments that connects target context, findings, remediation ownership, verification and evidence exports.'],
      ['Is it a replacement for a penetration test?','No. It performs defined non-destructive HTTP/TLS and configuration checks. Business logic, complex authorisation, source-code weaknesses and broader penetration testing still need qualified manual assessment.'],
      ['Can I scan any public website?','Only scan systems you own or have explicit permission to assess. Target and network-safety controls are designed to keep scope bounded.'],
      ['Does an OWASP mapping mean the application is compliant?','No. Mapping connects a specific observation to relevant references where justified. It does not certify the whole application or prove complete compliance.'],
      ['How is a remediation marked as fixed?','The team can request a fresh assessment and record whether the same issue is no longer observed or remains present. The original finding history stays available.']
    ],
    product:[
      ['What happens after a scan completes?','Review evidence and severity, open or correlate persistent findings, assign an owner and due date, document the decision, then verify the fix with a fresh assessment.'],
      ['Are scan settings preserved?','Completed scans keep execution and policy provenance so later reviewers can understand the configuration that produced the evidence.'],
      ['Does the asset inventory discover the entire internet-facing estate?','No. It records assets discovered within the authorised target and the crawler’s bounded same-origin scope.'],
      ['Can I export the evidence?','Available report formats include PDF, HTML and JSON, with scan context and export provenance where supported.']
    ],
    teams:[
      ['Who is SentinelScope for?','Application security, engineering and platform operations teams that need a repeatable assessment and remediation workflow. It can also support controlled education and research.'],
      ['How do teams collaborate on a finding?','The issue workflow can retain assignment, due dates, state, comments or rationale, occurrence history and verification outcome according to workspace permissions.'],
      ['Does it replace our engineering issue tracker?','It provides security-specific lifecycle context. Integrations and exports can help connect approved workflows, but do not assume it replaces every existing team system.']
    ],
    governance:[
      ['How are permissions handled?','Workspace roles are enforced by the API. System-administration capabilities are separated from ordinary workspace roles.'],
      ['Can risk be accepted without a reason?','Governed exceptions are designed to capture rationale, and some decisions can require approval and a future review date.'],
      ['Does an audit trail prove compliance?','It supports review of recorded actions and decisions; it is not, by itself, proof of regulatory compliance or an independent audit.']
    ],
    automation:[
      ['Can automation start a scan?','Approved automation can use scoped credentials and versioned endpoints where available. It remains subject to the same target authorisation and scanner safety controls.'],
      ['How are webhooks verified?','The developer workflow describes HMAC-SHA256 signatures for supported workspace event deliveries. Consumers should validate signatures and handle retries safely.'],
      ['Can an API key bypass UI permissions?','No. Bearer credentials are intended to be scoped to explicit permissions rather than act as an unrestricted user session.']
    ],
    onboarding:[
      ['What should I do first?','Secure the account, create a project, add the exact authorised HTTP(S) target, complete any required ownership verification, select a bounded profile and run the first assessment.'],
      ['Why might a target need verification?','Additional verification helps demonstrate control of the target before workflows that require a stronger authorisation signal.'],
      ['What should I review after the first baseline?','Check discovered assets, finding evidence and confidence, severity, standards references, ownership and remediation guidance before deciding what to fix first.']
    ],
    trust:[
      ['Does SentinelScope run destructive exploits?','The platform is designed for bounded, non-destructive checks and intentionally avoids destructive exploitation, credential attacks and denial-of-service behaviour.'],
      ['How are redirects handled?','Destination validation and redirect re-validation are part of the stated network safety model; operators should still define only authorised targets.'],
      ['Are standards mappings compliance certification?','No. They are evidence-level references to support review and do not replace full testing or independent certification.']
    ]
  };
  const key:any={features:'product','asset-inventory':'product','scan-profiles':'product','vulnerability-management':'product',reports:'product',workflow:'product','continuous-monitoring':'product','exposure-management':'product',solutions:'teams',enterprise:'governance',governance:'governance',developers:'automation',integrations:'automation',api:'automation',docs:'onboarding','getting-started':'onboarding',security:'trust','responsible-use':'trust',standards:'trust',trust:'trust',deployment:'governance',architecture:'governance',research:'product',methodology:'trust','scanner-checks':'trust',about:'product',status:'trust','404':'onboarding'};
  const items=group[key[page]||page]||group.product;
  return <section className="publicSection publicFaqSection"><div className="publicFaqIntro"><span className="pageHeroEyebrow"><span className="pageHeroDot"/> COMMON QUESTIONS</span><h2>Clear answers before you start.</h2><p>Understand the product boundary, the evidence it retains and the decisions that remain with your team.</p><a href="/docs">Read the platform guide <ArrowRight/></a></div><div className="publicFaqList">{items.map(([q,a]:string[],i:number)=><details key={q} className="publicFaqItem"><summary><span><small>0{i+1}</small>{q}</span><ChevronRight/></summary><p>{a}</p></details>)}</div></section>
}

function PageDeepDive({page,workflow}:any){
  const groupByPage:any={product:'product',features:'product','asset-inventory':'product','scan-profiles':'product','vulnerability-management':'product',reports:'product',workflow:'product','continuous-monitoring':'product','exposure-management':'product',solutions:'teams',enterprise:'governance',governance:'governance',developers:'automation',integrations:'automation',api:'automation',docs:'onboarding','getting-started':'onboarding',security:'trust','responsible-use':'trust',standards:'trust',trust:'trust',deployment:'governance',architecture:'governance',research:'product',methodology:'trust','scanner-checks':'trust',about:'product','404':'onboarding'};
  const group=groupByPage[page]||'product';
  const stories:any={
    product:{eyebrow:'INSIDE THE WORKSPACE',title:'One finding record. A clear next action.',text:'The important context stays connected: original evidence, check confidence, policy provenance, owner, due date, decision history and the verification result.',panel:'FINDING DETAIL',panelTitle:'HSTS missing on authenticated route',panelSub:'Customer portal · /account',status:'IN PROGRESS',owner:'Application Security',metric:'Evidence linked',foot:'Latest assessment · policy snapshot retained',steps:[['01','Capture the observation','Record the affected URL, response evidence and the check that produced the result.'],['02','Make ownership explicit','Assign the issue, due date and remediation decision so the next step is clear.'],['03','Verify before closure','Re-run a bounded assessment and preserve whether the issue is fixed or still present.']]},
    teams:{eyebrow:'ROLE-BASED HANDOFF',title:'Security, engineering and operations share the same evidence.',text:'Each role sees a different next action, but nobody has to reconstruct the issue from a detached report or an untracked chat thread.',panel:'TEAM HANDOFF',panelTitle:'CSP allows unsafe-inline',panelSub:'Marketing site · configuration review',status:'ASSIGNED',owner:'Web Engineering',metric:'Owner assigned',foot:'Triage notes and due date stay on the issue',steps:[['01','Security triages','Review severity, confidence, evidence and target criticality.'],['02','Engineering fixes','Use remediation guidance and keep investigation notes attached.'],['03','Security re-checks','Confirm the same finding is no longer observed before recording a verified outcome.']]},
    governance:{eyebrow:'GOVERNANCE IN PRACTICE',title:'Make every privileged action and risk decision reviewable.',text:'Access, risk acceptance, review dates, exports and activity history help explain who made a decision and what evidence was available at the time.',panel:'GOVERNED DECISION',panelTitle:'Temporary risk acceptance',panelSub:'Issue lifecycle · review required',status:'REVIEW DUE',owner:'Workspace Owner',metric:'Rationale recorded',foot:'Illustrative state · approval depends on workspace policy',steps:[['01','Enforce role boundaries','Keep workspace roles separate from platform-level administration.'],['02','Record the decision','Capture the reason, approver and future review date where policy requires it.'],['03','Revisit the exception','Use the review date and current evidence to renew or retire the decision.']]},
    automation:{eyebrow:'DEVELOPER WORKFLOW',title:'Automate the repeatable steps—not the safety boundary.',text:'Scoped API credentials, versioned endpoints, signed event delivery and structured exports help connect approved tools while retaining target and permission controls.',panel:'AUTOMATION EVENT',panelTitle:'Assessment completed',panelSub:'POST /api/v1/scans · illustrative',status:'SIGNED EVENT',owner:'Workspace integration',metric:'Scoped access',foot:'Validate webhook signatures and apply least privilege',steps:[['01','Authenticate narrowly','Use a credential with only the permissions required for the workflow.'],['02','Run approved work','The API still applies authorisation, policy limits and scanner safety checks.'],['03','Consume evidence safely','Validate event signatures, preserve export context and handle retries idempotently.']]},
    onboarding:{eyebrow:'GUIDED FIRST BASELINE',title:'A short path from a new account to useful evidence.',text:'A predictable setup sequence reduces mistakes: secure the account, define exact scope, choose bounded policy, then review results before assigning remediation.',panel:'WORKSPACE READINESS',panelTitle:'First baseline checklist',panelSub:'New workspace · illustrative state',status:'2 OF 4 STEPS',owner:'Workspace Owner',metric:'Next: verify target',foot:'The actual checklist reflects persisted workspace state',steps:[['01','Secure the account','Verify email, use a strong unique password and enable MFA when appropriate.'],['02','Define authorised scope','Create a project and add the exact target with owner, environment and criticality.'],['03','Run and review','Select a bounded profile, run the assessment and inspect evidence before acting.']]},
    trust:{eyebrow:'SAFETY & EVIDENCE BOUNDARIES',title:'Understand what the scanner does—and what it does not claim.',text:'SentinelScope favours bounded HTTP/TLS observations, transparent evidence and clear limitations over opaque exploit claims or blanket compliance language.',panel:'CHECK EVIDENCE',panelTitle:'Transport security observation',panelSub:'Target policy · redirect revalidation',status:'BOUNDED CHECK',owner:'Authorised target only',metric:'Evidence reviewable',foot:'A check result is not a complete security assurance',steps:[['01','Validate the destination','Apply scope and network destination controls before making a request.'],['02','Observe safely','Use bounded requests and record the evidence and confidence for each check.'],['03','Interpret in context','Combine automated results with manual review where logic, identity or architecture is involved.']]}
  };
  const s=stories[group]||stories.product;
  return <section className="publicSection pageDeepDiveSection"><div className="pageDeepDiveHeader"><div><span className="pageHeroEyebrow"><span className="pageHeroDot"/>{s.eyebrow}</span><h2>{s.title}</h2></div><p>{s.text}</p></div>
    <div className="pageDeepDiveGrid"><div className="pageDeepDiveSteps">{s.steps.map(([n,t,d]:string[])=><article key={n}><span>{n}</span><div><h3>{t}</h3><p>{d}</p></div><CheckCircle2/></article>)}</div>
      <div className="pageEvidenceMock"><div className="pageEvidenceMockTop"><div><span><i/> {s.panel}</span><small>ILLUSTRATIVE WORKSPACE VIEW</small></div><b><ShieldCheck/> POLICY LINKED</b></div><div className="pageEvidenceMockBody"><div className="pageEvidenceMockTitle"><span className="pageEvidenceMockSeverity">{s.status}</span><h3>{s.panelTitle}</h3><p>{s.panelSub}</p></div><div className="pageEvidenceMockCode"><small>EVIDENCE / CONTEXT</small><code>Observation recorded · target scope retained · source scan linked</code></div><div className="pageEvidenceMockFacts"><div><small>ACCOUNTABLE OWNER</small><b>{s.owner}</b></div><div><small>WORKFLOW SIGNAL</small><b>{s.metric}</b></div></div><div className="pageEvidenceMockFoot"><CheckCircle2/><span><b>History preserved</b><small>{s.foot}</small></span><ChevronRight/></div></div></div>
    </div>
    <WorkflowCompare variant={group}/>
  </section>
}

function ProductPreview(){
  return <div className="productPreview"><div className="previewChrome"><i/><i/><i/><span>SentinelScope / sample workspace</span><b className="previewSampleTag">ILLUSTRATIVE DATA</b></div><div className="previewBody"><aside><div className="previewLogo"><ShieldCheck/></div>{[Activity,FolderKanban,Globe2,TriangleAlert,FileText].map((I:any,i)=><span className={i===0?'on':''} key={i}><I/></span>)}</aside><div className="previewMain"><div className="previewHeader"><div><small>SECURITY OVERVIEW</small><b>Production estate</b></div><span><Search/> Search</span></div><div className="previewHero"><div><small>POSTURE</small><strong>82<em>/100</em></strong><p>4 priority actions need review</p></div><div className="miniBars"><i/><i/><i/><i/></div></div><div className="previewStats"><div><span>Open issues</span><b>18</b></div><div><span>Assets</span><b>147</b></div><div><span>Targets</span><b>8</b></div></div><div className="previewPanel"><div className="previewPanelHead"><b>Priority security actions</b><span>View all</span></div>{[['HIGH','HSTS missing on authenticated route','Customer portal'],['MEDIUM','CSP allows unsafe-inline','Marketing site'],['LOW','Technology banner disclosed','API gateway']].map(([s,t,d])=><div className="previewIssue" key={t}><span className={'severity '+s.toLowerCase()}>{s}</span><div><b>{t}</b><small>{d}</small></div><ChevronRight/></div>)}</div></div></div></div>
}

function PageVisual({page}:{page:string}){
  const presets:any={
    product:{kind:'assessment',badge:'ASSESSMENT COMPLETE',badgeValue:'82/100',badgeFoot:'+6 since last scan',eyebrow:'SECURITY OVERVIEW',heading:'Production estate',score:'82',scoreLabel:'Security posture',stats:[['Open issues','18'],['Assets','147'],['Targets','8']],rows:[['HIGH','HSTS missing on authenticated route','Customer portal'],['MEDIUM','CSP allows unsafe-inline','Marketing site'],['LOW','Technology banner disclosed','API gateway']],side:['Overview','Findings','Assets','Remediation','Evidence'],floatLabel:'FIX VERIFICATION',floatValue:'87%',floatFoot:'Re-checked against latest scan'},
    features:{kind:'capabilities',badge:'CHECK COVERAGE',badgeValue:'24 checks',badgeFoot:'Bounded & explainable',eyebrow:'ASSESSMENT PROFILE',heading:'Control coverage',score:'24',scoreLabel:'Enabled checks',stats:[['Transport','6'],['Browser','9'],['Disclosure','4']],rows:[['PASS','HTTPS and certificate checks','Transport'],['REVIEW','Content Security Policy quality','Browser controls'],['INFO','Security.txt availability','Discovery']],side:['Profiles','Transport','Browser','Forms','Evidence'],floatLabel:'EVIDENCE ATTACHED',floatValue:'100%',floatFoot:'For completed checks'},
    solutions:{kind:'team',badge:'TEAM WORKFLOW',badgeValue:'4 stages',badgeFoot:'One shared record',eyebrow:'WORK QUEUE',heading:'Team remediation',score:'18',scoreLabel:'Open issues',stats:[['Assigned','12'],['Overdue','3'],['Verified','26']],rows:[['HIGH','Assign an accountable owner','Application team'],['IN PROGRESS','Update remediation notes','Engineering'],['VERIFIED','Re-check the original issue','Security'],],side:['Portfolio','My issues','Teams','Decisions','History'],floatLabel:'OWNERSHIP COVERAGE',floatValue:'92%',floatFoot:'Issues with an owner'},
    enterprise:{kind:'governance',badge:'GOVERNANCE CHECK',badgeValue:'In control',badgeFoot:'Role and audit trails',eyebrow:'WORKSPACE GOVERNANCE',heading:'Access & accountability',score:'4',scoreLabel:'Workspace roles',stats:[['Members','12'],['Reviews due','2'],['Audit events','86']],rows:[['PASS','Workspace role enforced','Owner / Admin'],['REVIEW','Quarterly access review','Due this week'],['LOGGED','Risk decision recorded','Audit history']],side:['Access','Members','Reviews','Audit','Policy'],floatLabel:'AUDIT COVERAGE',floatValue:'100%',floatFoot:'Privileged actions logged'},
    developers:{kind:'developer',badge:'API CONNECTIVITY',badgeValue:'Healthy',badgeFoot:'Scoped credentials',eyebrow:'DEVELOPER PLATFORM',heading:'Assessment API',score:'v1',scoreLabel:'Versioned endpoints',stats:[['API keys','3'],['Webhooks','4'],['Exports','JSON']],rows:[['200','GET /api/v1/scans','Read scan history'],['POST','/api/v1/scans','Queue authorised scan'],['SIGNED','Webhook delivery','HMAC-SHA256']],side:['API','Keys','Webhooks','Exports','Events'],floatLabel:'REQUEST AUTH',floatValue:'Scoped',floatFoot:'Permission-bound access'},
    docs:{kind:'docs',badge:'GETTING STARTED',badgeValue:'4 steps',badgeFoot:'Guided setup',eyebrow:'DOCUMENTATION',heading:'Your first baseline',score:'04',scoreLabel:'Setup milestones',stats:[['Account','Secure'],['Target','Verify'],['Scan','Run']],rows:[['01','Secure the account','Verify email and sessions'],['02','Define authorised scope','Project and target'],['03','Review findings','Evidence and severity']],side:['Start','Scope','Assess','Triage','Verify'],floatLabel:'NEXT ACTION',floatValue:'Add target',floatFoot:'Keep scope explicit'},
    reports:{kind:'reporting',badge:'REPORT EXPORT',badgeValue:'Ready',badgeFoot:'Portable evidence',eyebrow:'ASSESSMENT REPORT',heading:'Baseline summary',score:'82',scoreLabel:'Posture score',stats:[['Findings','18'],['Mapped','14'],['Assets','147']],rows:[['PDF','Executive summary','Stakeholder review'],['HTML','Technical evidence','Browser review'],['JSON','Structured output','Automation'],],side:['Summary','Findings','Evidence','Standards','Export'],floatLabel:'EVIDENCE HASH',floatValue:'SHA-256',floatFoot:'Export provenance'},
    security:{kind:'trust',badge:'SAFETY BOUNDARY',badgeValue:'Enforced',badgeFoot:'Default-deny private targets',eyebrow:'SECURITY MODEL',heading:'Assessment guardrails',score:'0',scoreLabel:'Destructive actions',stats:[['Scope','Bounded'],['Redirects','Rechecked'],['Private IPs','Blocked']],rows:[['PASS','Destination validation','Before request'],['PASS','Redirect re-validation','Every hop'],['BLOCK','Private / metadata ranges','By default']],side:['Scope','Network','Identity','Audit','Limits'],floatLabel:'AUTHORISED TARGET',floatValue:'Required',floatFoot:'Before assessment'},
    standards:{kind:'standards',badge:'CONTROL MAPPING',badgeValue:'Evidence-led',badgeFoot:'No blanket compliance claims',eyebrow:'STANDARDS COVERAGE',heading:'Mapped observations',score:'14',scoreLabel:'Mapped checks',stats:[['OWASP WSTG','8'],['ASVS','6'],['Unmapped','10']],rows:[['MAPPED','Transport security','WSTG / ASVS'],['MAPPED','Cookie attributes','ASVS'],['REVIEW','Business logic','Manual assessment']],side:['Controls','WSTG','ASVS','Evidence','Limits'],floatLabel:'COMPLIANCE CLAIM',floatValue:'None',floatFoot:'Evidence supports review'},
    architecture:{kind:'architecture',badge:'SYSTEM DESIGN',badgeValue:'4 boundaries',badgeFoot:'Explicit components',eyebrow:'PLATFORM ARCHITECTURE',heading:'Assessment pipeline',score:'04',scoreLabel:'Core components',stats:[['Web UI','React'],['API','Flask'],['Worker','Queue']],rows:[['01','React application','User interaction'],['02','Flask API','Authorisation and policy'],['03','Worker queue','Bounded execution']],side:['UI','API','Queue','Scanner','Store'],floatLabel:'DATA FLOW',floatValue:'Traceable',floatFoot:'Persisted job history'},
    'asset-inventory':{kind:'assets',badge:'ASSET INVENTORY',badgeValue:'147 assets',badgeFoot:'8 authorised targets',eyebrow:'DISCOVERED SURFACE',heading:'Asset inventory',score:'147',scoreLabel:'Discovered assets',stats:[['Added','12'],['Changed','7'],['Removed','2']],rows:[['NEW','/account/settings','Customer portal'],['CHANGED','/api/v1/profile','API gateway'],['STABLE','/help/security','Help centre']],side:['Assets','Targets','Changes','Owners','History'],floatLabel:'BASELINE DRIFT',floatValue:'21',floatFoot:'Changes to review'},
    'vulnerability-management':{kind:'issues',badge:'ISSUE LIFECYCLE',badgeValue:'18 open',badgeFoot:'12 assigned',eyebrow:'REMEDIATION QUEUE',heading:'Persistent findings',score:'18',scoreLabel:'Issues to review',stats:[['High','4'],['Overdue','3'],['Verified','26']],rows:[['OPEN','HSTS missing on route','Owner needed'],['IN PROGRESS','CSP directive cleanup','Due in 2 days'],['VERIFIED','Cookie flags corrected','Closed after re-scan']],side:['Inbox','Assigned','Overdue','Risk','Verified'],floatLabel:'REMEDIATION SLA',floatValue:'92%',floatFoot:'Met in the last 30 days'},
    'scan-profiles':{kind:'profiles',badge:'PROFILE VERSION',badgeValue:'v3',badgeFoot:'Snapshot preserved',eyebrow:'SCAN CONFIGURATION',heading:'Production baseline',score:'v3',scoreLabel:'Reusable profile',stats:[['Pages','250'],['Depth','4'],['Pacing','Safe']],rows:[['IN SCOPE','Same-origin paths','Bounded crawl'],['ENABLED','TLS and browser controls','24 checks'],['LOCKED','Completed scan snapshot','Immutable'],],side:['Profiles','Scope','Checks','Schedules','Versions'],floatLabel:'POLICY PROVENANCE',floatValue:'Saved',floatFoot:'Per completed scan'},
    workflow:{kind:'workflow',badge:'WORKFLOW STATUS',badgeValue:'Connected',badgeFoot:'One issue record',eyebrow:'FROM SIGNAL TO ACTION',heading:'Finding lifecycle',score:'04',scoreLabel:'Connected stages',stats:[['Detected','1'],['Assigned','1'],['Verified','1']],rows:[['01','Detect with evidence','Scan completes'],['02','Assign an owner','Triage begins'],['03','Verify the fix','Fresh scan']],side:['Discover','Assess','Triage','Verify','Report'],floatLabel:'NEXT STEP',floatValue:'Verify fix',floatFoot:'Close only with evidence'}
  };
  const aliases:any={'exposure-management':'product','continuous-monitoring':'features',governance:'enterprise','getting-started':'docs',methodology:'security',trust:'security',status:'security',integrations:'developers',api:'developers',deployment:'architecture',research:'reports','scanner-checks':'features','responsible-use':'security',about:'architecture',workflow:'product','404':'docs'};
  const v=presets[page]||presets[aliases[page]]||presets.product;
  const bars=[30,48,40,64,52,76,60,92];
  return <div className={'pageVisual pageVisual-'+v.kind} aria-label={v.heading+' illustrative interface'}>
    <div className="pageVisualGlow" aria-hidden="true"/><div className="pageVisualOrb pageVisualOrbA" aria-hidden="true"/><div className="pageVisualOrb pageVisualOrbB" aria-hidden="true"/>
    <div className="pageVisualFloat pageVisualFloatTop"><span className="pageVisualFloatIcon"><CheckCircle2/></span><div><small>{v.badge}</small><b>{v.badgeValue}</b><em>{v.badgeFoot}</em></div><span className="pageVisualFloatSpark">{[3,5,4,7,6,9,8].map((h:number,i:number)=><i key={i} style={{height:(h*3)+'px'}}/>)}</span></div>
    <div className="pageVisualWindow"><div className="pageVisualChrome"><span/><span/><span/><b>SentinelScope <i>/</i> sample workspace</b><em>ILLUSTRATIVE</em></div>
      <div className="pageVisualApp"><aside className="pageVisualSide"><div className="pageVisualLogo"><ShieldCheck/></div>{v.side.map((s:string,i:number)=><span key={s} className={i===0?'active':''}>{i===0?<LayoutDashboard/>:i===1?<Radar/>:i===2?<FolderKanban/>:i===3?<Workflow/>:<FileText/>}<small>{s}</small></span>)}</aside>
        <div className="pageVisualMain"><div className="pageVisualMainHead"><div><small>{v.eyebrow}</small><b>{v.heading}</b></div><span><Search/> Search</span></div>
          <div className="pageVisualScore"><div><small>{v.scoreLabel}</small><b>{v.score}<em>{String(v.score).includes('/')?'':' '}{v.score==='82'?'/100':''}</em></b><small>Updated from the latest assessment</small></div><div className="pageVisualBars">{bars.map((h:number,i:number)=><i key={i} style={{height:h+'%'}}/>)}</div></div>
          <div className="pageVisualStats">{v.stats.map(([label,value]:string[])=><div key={label}><small>{label}</small><b>{value}</b></div>)}</div>
          <div className="pageVisualList"><div className="pageVisualListHead"><b>Priority actions</b><span>View all <ChevronRight/></span></div>{v.rows.map(([status,title,sub]:string[],i:number)=><div className="pageVisualRow" key={title}><span className={'pageVisualStatus status-'+status.toLowerCase().replaceAll(' ','-')}>{status}</span><div><b>{title}</b><small>{sub}</small></div><ChevronRight/></div>)}</div>
        </div>
      </div>
    </div>
    <div className="pageVisualFloat pageVisualFloatBottom"><span className="pageVisualFloatIcon pageVisualFloatIconBlue"><ShieldCheck/></span><div><small>{v.floatLabel}</small><b>{v.floatValue}</b><em>{v.floatFoot}</em></div></div>
    <div className="pageVisualCaption"><span><ShieldCheck/> Bounded by policy</span><span><FileText/> Evidence retained</span><span><CheckCircle2/> Reviewable results</span></div>
  </div>
}


function StaticPage({page}:{page:string}){
  const pages:any={
    product:{eyebrow:'PRODUCT WORKFLOW',title:'One governed path from authorised target to verified remediation.',intro:'SentinelScope connects the entire security assessment lifecycle: define approved scope, run bounded checks, correlate findings, assign remediation, verify the fix and retain reviewable evidence.',sectionTitle:'Every stage has a purpose—and a record.',sectionIntro:'The product keeps target context, policy provenance, finding state and verification history connected so a scan does not become a dead-end report.',sections:[
      ['Target management & authorisation','Create projects and exact HTTP(S) targets with environment, criticality, tags and an accountable owner. Explicit permission acknowledgement and required ownership verification keep the assessment boundary visible.',Globe2],
      ['Scan execution & policy','Run a bounded assessment using reusable profiles for page limits, crawl depth, pacing, path scope and enabled checks. Completed scans retain the policy snapshot used for that run.',Radar],
      ['Issue detection & evidence','Capture the affected URL, response evidence, severity, confidence, impact, remediation guidance and standards references where justified.',TriangleAlert],
      ['Prioritisation & ownership','Use severity, target criticality, recurrence, assignment and due dates to decide what needs attention first. Keep investigation notes and risk rationale on the issue.',Users],
      ['Remediation workflow','Move persistent findings through acknowledgement, in-progress work, governed risk acceptance or false-positive review without losing the detection history.',Workflow],
      ['Verification scans','Queue a fresh bounded assessment after a fix and record whether the same fingerprint is no longer observed or remains present.',GitCompareArrows],
      ['Reporting & evidence export','Prepare PDF, HTML or JSON reports with scan context, mapped checks, issue evidence and export provenance where supported.',FileText],
      ['Audit trail & operations','Retain user actions, role boundaries, scan history, worker/queue visibility, schedules and operational controls for later review.',History]
    ],workflow:[
      ['01','Define authorised scope','Create a project and verify the exact target and its business context.',Globe2],
      ['02','Run a bounded assessment','Apply a named policy and capture repeatable evidence.',Radar],
      ['03','Assign and remediate','Correlate findings, set an owner and due date, and record the decision.',Workflow],
      ['04','Verify and report','Re-assess the target, record the outcome and preserve the evidence.',CheckCircle2]
    ]},
    features:{eyebrow:'CAPABILITY MAP',title:'Eight connected capability groups. One consistent operating model.',intro:'Features are grouped around the work teams need to complete—not a flat list of technical checkboxes. Each module connects to the same permission, evidence and lifecycle model.',sectionTitle:'Explore the platform by the job to be done.',sectionIntro:'From the first approved target to reporting and team handoff, these modules share context rather than creating separate islands of data.',sections:[
      ['Assessment & scan profiles','Configure bounded crawl depth, page limits, pacing, path scope and enabled checks. Reuse named, versioned profiles and preserve the exact policy snapshot for each completed scan.',Radar],
      ['Findings & prioritisation','Review severity, confidence, evidence, impact and remediation guidance. Correlate repeated detections and use target criticality, due dates and state to focus the queue.',TriangleAlert],
      ['Asset inventory & exposure','Keep discovered same-origin assets, source pages, response metadata, provenance and baseline drift connected to the authorised targets that produced them.',Globe2],
      ['Workflow & remediation','Assign accountable owners, track status, add investigation notes, govern risk decisions and verify a fix through a new assessment.',Workflow],
      ['Governance & access','Use workspace roles, invitations, session controls, MFA, scoped API keys, access reviews and separation between workspace and platform administration.',LockKeyhole],
      ['Reporting & standards mapping','Export PDF, HTML and JSON evidence. Map individual checks to relevant OWASP WSTG/ASVS references without claiming blanket compliance.',FileText],
      ['Automation & integrations','Use scoped credentials, versioned endpoints, signed webhooks, recurring schedules and machine-readable exports for approved workflows.',Braces],
      ['Team collaboration & audit','Keep assignments, due dates, comments, activity, risk rationale, review dates and recorded administrative actions available to the right workspace roles.',Users]
    ],workflow:[
      ['01','Configure','Choose a reusable profile and define the authorised assessment boundary.',SlidersHorizontal],
      ['02','Observe','Collect bounded findings, assets and evidence from a completed scan.',Radar],
      ['03','Coordinate','Use shared ownership and issue state to move remediation forward.',Users],
      ['04','Prove','Re-check the change and export evidence for review.',CheckCircle2]
    ]},
    'exposure-management':{eyebrow:'CONTEXTUAL EXPOSURE',title:'Connect governed scope, discovered surface, active risk and accountable ownership.',intro:'SentinelScope builds an exposure view from its own persisted project, target, asset and finding relationships. It helps teams prioritise real assessment context without claiming internet-wide attack-surface discovery.',sections:[
      ['Relationship map','Projects connect to authorised targets, targets connect to discovered same-origin assets and persistent issues, and assigned issues connect to workspace owners.',Network],
      ['Contextual prioritisation','Lifecycle risk score, effective severity, target criticality, overdue state and ownership are brought together so teams can focus on the highest-impact work first.',TriangleAlert],
      ['Evidence-backed inventory','Every relationship is derived from persisted workspace data: target governance, scanner discovery, stable finding fingerprints and team assignments.',Database],
      ['Operational handoff','Move directly from the exposure view into the asset inventory or issue inbox to investigate evidence, assign work and verify remediation.',Workflow]
    ]},
    'asset-inventory':{eyebrow:'ATTACK SURFACE CONTEXT',title:'Know what was actually discovered, who owns it and what changed.',intro:'SentinelScope persists same-origin discovery as a working asset inventory rather than discarding crawler output after each scan.',sections:[
      ['Persistent discovered assets','URLs, source page, depth, response status, content type, title, size, timing, redirect evidence and truncation state remain attached to scan evidence.',Globe2],
      ['Business context','Targets carry environment, criticality, tags, accountable owner and operational notes so technical evidence can be prioritised with real context.',Users],
      ['Drift between baselines','Successive scans identify added, removed and meaningfully changed assets while suppressing trivial response-size noise.',GitCompareArrows],
      ['Historical provenance','Asset drill-down preserves first seen, last seen, scan score and change history without pretending crawler discovery is full internet attack-surface discovery.',History]
    ]},
    'scan-profiles':{eyebrow:'ASSESSMENT GOVERNANCE',title:'Reusable, versioned scan profiles without losing historical truth.',intro:'Teams should configure recurring assessment behaviour once and reuse it. SentinelScope keeps profiles editable for future work while every scan records immutable execution provenance.',sections:[
      ['Named reusable profiles','Create Production Baseline, Release Gate, Low-impact Daily or Verified Lab configurations inside each project.',SlidersHorizontal],
      ['Bounded configuration','Profiles control mode, maximum pages, crawl depth, pacing, include/exclude path patterns and disabled checks within platform safety caps.',ServerCog],
      ['Version-aware execution','Editing a profile creates the next version for future runs. Completed scans retain the profile name/version and exact policy snapshot that produced their evidence.',History],
      ['Manual and recurring reuse','The same profile can drive an ad-hoc authorised assessment or a recurring schedule, reducing configuration drift.',CalendarClock]
    ]},
    'vulnerability-management':{eyebrow:'ISSUE OPERATIONS',title:'Treat findings as owned security work, not disposable scan output.',intro:'Stable fingerprints connect repeated detections to one lifecycle record with accountability, deadlines, risk decisions and independent re-verification.',sections:[
      ['Persistent lifecycle','OPEN, ACKNOWLEDGED, IN_PROGRESS, ACCEPTED_RISK, FALSE_POSITIVE and REMEDIATED states survive across individual scans.',Workflow],
      ['Ownership & SLA','Assignments, severity-aware due dates, overdue escalation and workspace risk policy make backlog responsibility visible.',Users],
      ['Governed exceptions','Risk acceptance and false-positive decisions require rationale; acceptance can require Owner approval and a future review date.',ShieldCheck],
      ['Verification loop','After remediation, queue a fresh bounded assessment and record VERIFIED_FIXED or STILL_PRESENT against the same fingerprint.',GitCompareArrows]
    ]},
    'continuous-monitoring':{eyebrow:'CONTINUOUS ASSESSMENT',title:'Repeat the same governed assessment and know when its health changes.',intro:'Recurring schedules bind authorised targets to reusable assessment configuration and keep durable execution history rather than acting like anonymous cron jobs.',sections:[
      ['Named schedules','Set the target, reusable scan profile, cadence and failure-notification preference with pause/resume controls.',CalendarClock],
      ['Execution health','Track next/last run, run count, failure count, worker state and persisted run history from the workspace.',Activity],
      ['Durable queue','SQLite-backed jobs survive API restarts, use bounded retry/backoff and stale-lease recovery, and remain visible to administrators.',Database],
      ['Operational alerts','Scheduled failures, overdue findings and signed webhook events can move important changes into the team workflow.',Webhook]
    ]},
    governance:{eyebrow:'SECURITY GOVERNANCE',title:'Separate workspace decisions, platform administration and evidence ownership.',intro:'Enterprise control is more than RBAC. SentinelScope keeps membership, access review, risk acceptance, audit, evidence export and system administration as explicit workflows.',sections:[
      ['Workspace roles','Owner, Admin, Analyst and Viewer permissions are API-enforced and isolated per workspace.',LockKeyhole],
      ['Access certification','Snapshot membership, review keep/revoke decisions, protect the Owner role and invalidate sessions when access is revoked.',Users],
      ['Evidence governance','Audit events, finding activity, report-export hashes, risk rationale and verification history preserve who changed what and when.',History],
      ['Platform separation','System administration remains a separate privilege for workers, jobs, global users/workspaces, backups, maintenance and security telemetry.',ServerCog]
    ]},
    'getting-started':{eyebrow:'GETTING STARTED',title:'Go from empty workspace to a trustworthy first baseline.',intro:'The product includes a readiness journey that derives progress from real persisted state, so new teams always know the next safe step.',sections:[
      ['1. Secure the account','Verify email, configure MFA when appropriate and review active sessions.',LockKeyhole],
      ['2. Establish scope','Create an active project, add the exact authorised HTTP(S) target and attach owner, environment, criticality and notes.',FolderKanban],
      ['3. Govern execution','Use the project baseline or create a named scan profile, then verify ownership before any Lab-mode workflow.',SlidersHorizontal],
      ['4. Create evidence','Run the first assessment, review discovered assets and issues, assign remediation and schedule repeatable follow-up.',Radar]
    ]},
    methodology:{eyebrow:'METHODOLOGY',title:'What the scanner measures, how it gathers evidence and where automation stops.',intro:'SentinelScope is deliberately transparent about safe HTTP/TLS observations, heuristics, confidence and limitations so results can be evaluated instead of treated as oracle output.',sections:[
      ['Transport & browser controls','Inspect TLS/certificate evidence, HTTPS/HSTS, headers, cookies, mixed content and related browser-facing configuration.',ShieldCheck],
      ['Bounded application observation','Same-origin crawling, forms, CORS behaviour, advertised methods, disclosure signals and security.txt are assessed without destructive payload execution.',Radar],
      ['Evidence & confidence','Each check records status, severity, confidence, URL, evidence, impact, remediation and standards mapping where justified.',FileText],
      ['Known limits','Business logic, complex authorization, architecture, human process and source-only weaknesses still require manual security review.',BookOpen]
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
    '404':{eyebrow:'404',title:'This page does not exist.',intro:'The address may be incorrect or the page may have moved. Use the links below to return to a known SentinelScope destination.',sections:[
      ['Return home','Go back to the public SentinelScope overview and product entry points.',Globe2],
      ['Open documentation','Review platform workflow, scanner methodology, security model and deployment guidance.',BookOpen],
      ['Sign in','If you were looking for your security workspace, use the sign-in page.',LockKeyhole]
    ]},
    about:{eyebrow:'ABOUT THE PROJECT',title:'A transparent security-assessment platform built for explainability.',intro:'SentinelScope focuses on clear methodology, reproducible evidence and safe operation rather than opaque “magic” vulnerability claims.',sections:[
      ['Purpose','Help students, small teams and security practitioners understand repeatable web-security checks and track remediation in a controlled workflow.',ShieldCheck],
      ['Architecture','React + TypeScript frontend, Flask API, SQLite WAL persistence, separate worker process and Docker/Nginx deployment option.',Database],
      ['Evaluation mindset','Controlled secure/insecure demonstration targets, regression tests, browser E2E and optional OWASP ZAP result comparison support measurable evaluation.',GitCompareArrows],
      ['Responsible use','Only assess systems you own or are explicitly authorised to test. The scanner is designed to remain non-destructive.',LockKeyhole]
    ]}
  };
  const p=pages[page]||pages.product;
  const workflow=p.workflow||p.sections.slice(0,4);
  return <main className="publicInnerPage">
    <section className="pageHero pageHeroVisual">
      <div className="pageHeroCopy">
        <div className="pageHeroEyebrow"><span className="pageHeroDot"/>{p.eyebrow} <span className="pageHeroEyebrowDivider">/</span> SENTINELSCOPE PLATFORM</div>
        <h1>{p.title}</h1>
        <p>{p.intro}</p>
        <div className="heroCtas pageHeroActions"><a className="publicPrimary large" href="/signup">Create workspace <ArrowRight/></a><a className="publicSecondary" href="/workflow"><Workflow/> See how it works</a></div>
        <div className="pageHeroProof"><span><CheckCircle2/> Authorisation-first</span><span><FileText/> Evidence-backed</span><span><Activity/> Remediation-focused</span></div>
      </div>
      <PageVisual page={page}/>
    </section>
    <section className="publicSection pageDetailSection">
      <SectionHead eyebrow="WHAT YOU CAN DO" title={p.sectionTitle||"Turn the capability into an accountable workflow."} text={p.sectionIntro||"Each capability is designed to produce a clear next step, preserve the evidence behind decisions and keep the work connected to its owner."}/>
      <div className="detailGrid pageDetailGrid">{p.sections.map(([t,d,I]:any,i:number)=><article key={t} style={{'--detail-index':i} as any}><div className="detailCardTop"><span>0{i+1}</span><I/></div><h2>{t}</h2><p>{d}</p><div className="detailCardFoot"><span>WORKFLOW CAPABILITY</span><CheckCircle2/></div></article>)}</div>
    </section>
    <section className="publicSection pageWorkflowSection">
      <div className="pageWorkflowHeading"><div><span className="pageHeroEyebrow"><span className="pageHeroDot"/> FROM SIGNAL TO ACTION</span><h2>Make every step visible. Keep every decision connected.</h2></div><p>Follow the work from the initial assessment through triage, ownership and verification—with evidence retained along the way.</p></div>
      <div className="pageWorkflowRail">{workflow.map(([t,d,I]:any,i:number)=><article key={t}><span className="pageWorkflowNumber">0{i+1}</span><div className="pageWorkflowIcon"><I/></div><h3>{t}</h3><p>{d}</p>{i<workflow.length-1&&<span className="pageWorkflowConnector" aria-hidden="true"><ArrowRight/></span>}</article>)}</div>
    </section>
    <PageDeepDive page={page} workflow={workflow}/>
    <PublicFaq page={page}/>
    <section className="publicCTA pageBottomCta"><div><span>AUTHORISATION FIRST · EVIDENCE ALWAYS</span><h2>Security tooling is useful when findings become verified, accountable work.</h2><p>Start with a target you are authorised to assess. Keep the scope bounded and the evidence reviewable.</p></div><a className="publicPrimary large" href="/signup">Create workspace <ArrowRight/></a></section>
  </main>
}

function SectionHead({eyebrow,title,text}:any){return <div className="sectionHead"><span>{eyebrow}</span><h2>{title}</h2><p>{text}</p></div>}

function StatusPage(){
  const[health,setHealth]=useState<any>(null),[error,setError]=useState('');
  useEffect(()=>{let live=true;const check=async()=>{try{const r=await fetch('/health',{cache:'no-store'});const d=await r.json();if(!r.ok)throw new Error('Health endpoint returned '+r.status);if(live){setHealth(d);setError('')}}catch(e:any){if(live)setError(e.message||'Service health could not be checked')}};check();const id=setInterval(check,30000);return()=>{live=false;clearInterval(id)}},[]);
  const ok=health?.status==='ok'&&!error;
  return <main className="publicInnerPage"><section className="pageHero pageHeroVisual statusHero"><div className="pageHeroCopy"><div className="pageHeroEyebrow"><span className="pageHeroDot"/><span>PLATFORM STATUS</span><span className="pageHeroEyebrowDivider">/</span> PUBLIC HEALTH</div><h1>Operational transparency without exposing sensitive telemetry.</h1><p>This page reads SentinelScope's public-safe health endpoint. Administrative metrics, worker internals, security events and queue details remain authenticated.</p><div className="heroCtas pageHeroActions"><a className="publicPrimary large" href="/security">Review security model <ArrowRight/></a><a className="publicSecondary" href="/trust"><ShieldCheck/> Trust & governance</a></div></div><PageVisual page="status"/></section>
  <section className="publicSection"><div className={'statusBanner '+(ok?'operational':error?'degraded':'checking')}><span className="statusPulse"/><div><b>{ok?'All public platform checks operational':error?'Service health check unavailable':'Checking platform health…'}</b><p>{ok?'API health is responding normally.':error?error:'Waiting for the public health endpoint.'}</p></div><small>{new Date().toLocaleString()}</small></div>
  <div className="statusComponents">{[['API service',health?.status==='ok'],['Persistence layer',health?.database==='sqlite'],['Worker queue',health?.queue==='sqlite-worker']].map(([name,state]:any)=><article key={name}><div><b>{name}</b><small>Public-safe component signal</small></div><span className={'componentState '+(state?'good':'unknown')}>{state?'OPERATIONAL':'CHECKING'}</span></article>)}</div>
  <div className="statusTrust"><ShieldCheck/><div><h2>Why this page is intentionally minimal</h2><p>Detailed worker heartbeats, job failures, audit logs, security events, database sizes and operational controls belong in the authenticated System Admin console. The public status view exposes only the information necessary to confirm basic service availability.</p></div></div></section><PublicFaq page="status"/></main>
}
