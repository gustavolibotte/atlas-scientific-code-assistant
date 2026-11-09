import { useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import {
  Activity, ArrowDownRight, ArrowRight, ArrowUpRight, BookOpen, CheckCircle2,
  ChevronDown, Code2, Command, Cpu, FileCode2, FlaskConical, FolderKanban,
  GitBranch, Home, Layers3, LockKeyhole, Menu, Plug2, Search,
  Send, Settings2, ShieldCheck, Sparkles, TerminalSquare, X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { getSystemState } from "./api";
import type { SystemState } from "./api";

const TABS = ["Overview", "Workspace", "Evidence", "Validation", "Settings"] as const;
type Tab = (typeof TABS)[number];

const NAV: { tab: Tab; icon: LucideIcon }[] = [
  { tab: "Overview", icon: Home },
  { tab: "Workspace", icon: FolderKanban },
  { tab: "Evidence", icon: BookOpen },
  { tab: "Validation", icon: FlaskConical },
  { tab: "Settings", icon: Settings2 },
];

const EMPTY_STATE: SystemState = {
  connected: false, version: null, capabilities: [], trace: null, error: null,
};

function StatusPill({ state }: { state: SystemState }) {
  return (
    <span className={`status-pill ${state.connected ? "online" : "offline"}`}>
      <span className="status-dot" />
      {state.connected ? "API connected" : "API offline"}
    </span>
  );
}

function Sidebar({ active, navigate, open, close }: {
  active: Tab; navigate: (tab: Tab) => void; open: boolean; close: () => void;
}) {
  return (
    <aside className={`sidebar ${open ? "sidebar-open" : ""}`}>
      <div className="brand-row">
        <div className="brand-symbol"><Layers3 size={21} strokeWidth={2.4} /></div>
        <div><strong>ASCA</strong><span>Scientific workspace</span></div>
        <button className="mobile-close" type="button" onClick={close} aria-label="Close navigation"><X size={18} /></button>
      </div>
      <div className="sidebar-workspace">
        <span className="side-label">CURRENT SPACE</span>
        <div className="workspace-select"><div className="workspace-avatar">S</div><div><strong>Research Lab</strong><small>Local development</small></div><ChevronDown size={16}/></div>
      </div>
      <nav aria-label="Main navigation">
        <span className="side-label">WORKSPACE</span>
        {NAV.map(({ tab, icon: Icon }) => (
          <button type="button" key={tab} onClick={() => { navigate(tab); close(); }}
            className={`nav-item ${active === tab ? "active" : ""}`} aria-current={active === tab ? "page" : undefined}>
            <Icon size={18} /><span>{tab}</span>{tab === "Evidence" && <span className="nav-soon">Demo</span>}
          </button>
        ))}
      </nav>
      <div className="sidebar-spacer" />
      <div className="sidebar-notice">
        <div className="sidebar-orbit"><Sparkles size={22}/></div>
        <strong>Evidence first.</strong>
        <p>Scientific decisions should be traceable to sources and tests.</p>
        <span>Foundation release</span>
      </div>
      <div className="sidebar-bottom"><div className="user-avatar">L</div><div><strong>Local researcher</strong><small>Phase 0 · No sign-in</small></div><span className="bottom-menu">···</span></div>
    </aside>
  );
}

function Overview({ state, navigate }: { state: SystemState; navigate: (tab: Tab) => void }) {
  const available = state.capabilities.filter((cap) => cap.status === "available").length;
  return (
    <>
      <section className="hero">
        <div className="hero-content"><div className="hero-eyebrow"><Sparkles size={15}/> THE NEXT GENERATION OF SCIENTIFIC TOOLS</div>
          <h2>Build science<br/><em>you can explain.</em></h2>
          <p>From scientific evidence to reproducible code. A workspace for rigorously grounded research software.</p>
          <button className="primary-btn" type="button" onClick={() => navigate("Workspace")}>Explore workspace <ArrowRight size={17}/></button>
        </div>
        <div className="hero-art" aria-hidden="true">
          <div className="orbit orbit-1"/><div className="orbit orbit-2"/><div className="orbit orbit-3"/>
          <div className="orb orb-a"/><div className="orb orb-b"/><div className="orb orb-c"/>
          <div className="hero-core"><Code2 size={40}/></div>
          <span className="hero-hint hint-a">Evidence</span><span className="hero-hint hint-b">Code</span><span className="hero-hint hint-c">Validation</span>
        </div>
      </section>
      <div className="section-heading"><div><p className="eyebrow">FOUNDATION</p><h3>Environment overview</h3></div><button className="text-action" onClick={() => navigate("Validation")} type="button">View checks <ArrowUpRight size={16}/></button></div>
      <div className="stats-grid">
        <div className="stat-card"><div className="stat-icon violet"><Activity size={19}/></div><span>API status</span><strong>{state.connected ? "Connected" : "Offline"}</strong><small>{state.connected ? `Version ${state.version}` : "Start the backend to connect"}</small></div>
        <div className="stat-card"><div className="stat-icon blue"><Plug2 size={19}/></div><span>Available capabilities</span><strong>{state.connected ? `${available} / ${state.capabilities.length}` : "—"}</strong><small>No CERN integrations configured</small></div>
        <div className="stat-card"><div className="stat-icon peach"><ShieldCheck size={19}/></div><span>Evidence state</span><strong>Demo only</strong><small>No published sources linked</small></div>
      </div>
      <div className="content-grid">
        <section className="panel featured-panel"><div className="panel-title"><div><p className="eyebrow">YOUR WORKSPACE</p><h3>Scientific development pipeline</h3></div><span className="subtle-label">Planned workflow</span></div>
          <div className="process-list">
            {[
              {icon:Search, name:"Retrieve knowledge", desc:"chATLAS, published literature, source repositories", status:"Planned"},
              {icon:GitBranch, name:"Trace scientific decisions", desc:"Evidence → choice → implementation → test", status:"Demo"},
              {icon:TerminalSquare, name:"Generate and validate code", desc:"Safe execution, numerical checks, reproducible results", status:"Planned"},
            ].map(({ icon: Icon, name, desc, status }) => <div className="process-row" key={name}><div className="process-icon"><Icon size={19}/></div><div><strong>{name}</strong><small>{desc}</small></div><span className="process-state">{status}</span></div>)}
          </div>
        </section>
        <section className="panel side-panel"><div className="panel-title"><div><p className="eyebrow">TRACEABILITY</p><h3>Inspect a decision</h3></div><div className="trace-figure"><GitBranch size={18}/></div></div>
          <p>Explore how a scientific decision will connect to its sources, code symbols, and verification results.</p>
          <div className="trace-stages"><span>Source</span><ArrowDownRight size={16}/><span>Decision</span><ArrowDownRight size={16}/><span>Test</span></div>
          <button className="secondary-btn" type="button" onClick={() => navigate("Evidence")}>Open synthetic example <ArrowRight size={16}/></button>
        </section>
      </div>
    </>
  );
}

function Workspace() {
  const [prompt, setPrompt] = useState("");
  const [preview, setPreview] = useState("");
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (prompt.trim()) { setPreview(prompt.trim()); setPrompt(""); }
  }
  return (
    <section className="workspace-layout">
      <div className="panel conversation-panel">
        <div className="panel-title"><div><p className="eyebrow">YOUR RESEARCH ASSISTANT</p><h3>Scientific conversation</h3></div><span className="subtle-label">Local preview</span></div>
        <div className="conversation-body"><div className="assistant-bubble"><div className="bubble-icon"><Sparkles size={17}/></div><div><strong>Welcome to your scientific workspace.</strong><p>Future conversations will combine scientific references, implementation decisions, and reproducible tests. The agent is not connected in Phase 0.</p></div></div>
          {preview && <div className="draft-preview"><strong>Local draft preview</strong><p>{preview}</p><small>Not sent to an AI model. No code was generated.</small></div>}
        </div>
        <form className="composer" onSubmit={submit}><label htmlFor="prompt">Describe a scientific coding task</label><textarea id="prompt" rows={3} maxLength={2000} value={prompt} onChange={(event) => setPrompt(event.target.value)} placeholder="e.g. Compare linear amplitude estimators using an ATLAS methodology..."/><div className="composer-footer"><span>Preview only · Not sent to a model</span><button type="submit" className="primary-btn" disabled={!prompt.trim()}>Preview draft <Send size={15}/></button></div></form>
      </div>
      <div className="workspace-aside"><div className="panel"><div className="panel-title"><h3>Planned outputs</h3><Code2 size={18}/></div><div className="file-list"><div><FileCode2 size={18}/> Python implementation</div><div><FlaskConical size={18}/> Scientific tests</div><div><BookOpen size={18}/> Evidence manifest</div><div><ShieldCheck size={18}/> Validation report</div></div></div>
        <div className="note-card"><LockKeyhole size={19}/><strong>Safe by design</strong><p>No command execution or external document access is enabled in the foundation.</p></div></div>
    </section>
  );
}

function EvidenceView({ state }: { state: SystemState }) {
  const trace = state.trace;
  return <div className="content-grid evidence-grid"><section className="panel featured-panel"><div className="panel-title"><div><p className="eyebrow">PROVENANCE EXPLORER</p><h3>Decision → evidence → verification</h3></div><span className="demo-label">SYNTHETIC DEMO</span></div>
    {trace ? <><div className="evidence-detail"><span className="detail-key">SCIENTIFIC DECISION</span><h4>{trace.decision.statement}</h4><p>{trace.decision.rationale}</p></div>
      <div className="evidence-line"><div className="evidence-tag"><BookOpen size={17}/> Source</div><strong>{trace.evidence[0]?.title}</strong><small>{trace.evidence[0]?.locator} · unverified</small></div>
      <div className="evidence-line"><div className="evidence-tag"><Code2 size={17}/> Code symbol</div><strong>{trace.symbols[0]?.qualified_name}()</strong><small>{trace.symbols[0]?.file_path} · synthetic revision</small></div>
      <div className="evidence-line"><div className="evidence-tag"><FlaskConical size={17}/> Verification</div><strong>{trace.verifications[0]?.label}</strong><small>State: {trace.verifications[0]?.state}</small></div>
      <p className="alert-note">{trace.disclaimer}</p>
    </> : <div className="empty-state"><Plug2 size={26}/><p>Connect the API to inspect the synthetic example.</p></div>}
  </section><section className="panel side-panel"><div className="panel-title"><h3>What provenance means</h3><GitBranch size={18}/></div><p>Every real decision will have a reference to its source and a versioned code symbol. A passing test will never be presented as scientific collaboration approval.</p><div className="note-card compact"><ShieldCheck size={18}/><span>All source references shown in Phase 0 are synthetic placeholders.</span></div></section></div>;
}

function ValidationView() {
  return <div className="content-grid"><section className="panel featured-panel"><div className="panel-title"><div><p className="eyebrow">QUALITY GATES</p><h3>Reproducible checks</h3></div><FlaskConical size={20}/></div>
    <div className="process-list">{["Python unit and property tests", "API contract and security checks", "Architecture dependency tests", "Static typing and linting", "Frontend build and component tests"].map((name)=><div className="process-row" key={name}><div className="process-icon"><CheckCircle2 size={18}/></div><div><strong>{name}</strong><small>Run locally to establish a verified result</small></div><span className="process-state">Not run</span></div>)}</div>
    <div className="command-box"><TerminalSquare size={18}/><code>uv run python scripts/run_checks.py</code></div></section>
    <section className="panel side-panel"><h3>Share results</h3><p>After the full local run, share the generated diagnostic ZIP for review. This page does not claim that any check has passed.</p><div className="note-card compact"><ShieldCheck size={19}/><span>Required review gate: every change, every phase.</span></div></section></div>;
}

function SettingsView({ state }: { state: SystemState }) {
  return <section className="panel settings-panel"><div className="panel-title"><div><p className="eyebrow">SYSTEM SETTINGS</p><h3>Integration readiness</h3></div><Settings2 size={19}/></div>
    {state.capabilities.length > 0 ? state.capabilities.map((item)=><div className="settings-row" key={item.id}><div><strong>{item.label}</strong><small>{item.id}</small></div><span className={`capability-state ${item.status}`}>{item.status.replaceAll("_", " ")}</span></div>) : <div className="empty-state"><Plug2 size={24}/><p>Start the local API to load actual capability states.</p></div>}
    <p className="alert-note">CERN SSO, chATLAS, and code execution are not implemented in this release. Do not enter credentials here.</p>
  </section>;
}

export default function App() {
  const [active, setActive] = useState<Tab>("Overview");
  const [menuOpen, setMenuOpen] = useState(false);
  const [state, setState] = useState<SystemState>(EMPTY_STATE);
  useEffect(() => {
    const controller = new AbortController();
    void getSystemState(controller.signal).then(setState).catch(() => undefined);
    return () => controller.abort();
  }, []);
  const subtitle = useMemo(() => ({
    Overview: "Your environment for evidence-grounded scientific software",
    Workspace: "Converse, plan, and develop with scientific context",
    Evidence: "Understand the scientific basis of every implementation",
    Validation: "See the checks required before accepting any change",
    Settings: "Manage capabilities and integration readiness",
  }[active]), [active]);
  return <div className="app-shell"><Sidebar active={active} navigate={setActive} open={menuOpen} close={()=>setMenuOpen(false)}/>
    <main className="main"><header className="topbar"><div className="top-left"><button className="mobile-menu" type="button" aria-label="Open navigation" onClick={()=>setMenuOpen(true)}><Menu size={21}/></button><span className="breadcrumbs">Research Lab</span><span className="slash">/</span><strong>{active}</strong></div><div className="top-right"><span className="phase-tag">FOUNDATION · 0.1.0</span><StatusPill state={state}/><span className="top-avatar">L</span></div></header>
    <div className="page"><div className="page-heading"><div><p className="eyebrow">SCIENTIFIC ENGINEERING</p><h1>{active === "Overview" ? "Good to see you." : active}</h1><p>{subtitle}</p></div><div className="heading-icon"><Command size={24}/></div></div>
      {!state.connected && <div className="connection-warning" role="status"><Plug2 size={17}/>Backend disconnected. Start FastAPI to enable live status and the synthetic trace. {state.error && <span className="error-detail">{state.error}</span>}</div>}
      {active === "Overview" && <Overview state={state} navigate={setActive}/>}
      {active === "Workspace" && <Workspace/>}
      {active === "Evidence" && <EvidenceView state={state}/>}
      {active === "Validation" && <ValidationView/>}
      {active === "Settings" && <SettingsView state={state}/>}
      <footer className="footer"><span>ASCA · Foundation release · Not an official CERN or ATLAS product</span><span>No external services connected <Cpu size={14}/></span></footer>
    </div></main>
    {menuOpen && <button aria-label="Close navigation overlay" className="mobile-scrim" type="button" onClick={()=>setMenuOpen(false)}/>}
  </div>;
}
