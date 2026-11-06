
import {
  Activity,
  ArrowUpRight,
  CheckCircle2,
  CircleAlert,
  Code2,
  FileCode2,
  FolderGit2,
  Gauge,
  LayoutDashboard,
  Package,
  RefreshCw,
  ScanSearch,
  Settings,
  ShieldCheck,
  Terminal,
  TriangleAlert,
  Zap,
} from "lucide-react";

const checks = [
  { name: "SDK detection", detail: "SDK packages identified", status: "Passed", icon: Package },
  { name: "Dependency compatibility", detail: "Version compatibility analysis", status: "Pending", icon: FolderGit2 },
  { name: "Deprecated API detection", detail: "Scanning for outdated APIs", status: "Pending", icon: Code2 },
  { name: "Locklift configuration", detail: "Configuration validation", status: "Pending", icon: Settings },
  { name: "Compiler configuration", detail: "Compiler and network settings", status: "Pending", icon: FileCode2 },
];

const issues = [
  { severity: "Warning", title: "SDK compatibility not verified", description: "Run a scan to check whether installed SDK versions work together.", color: "warning" },
  { severity: "Info", title: "No project scan performed", description: "Connect a project to generate its first health report.", color: "info" },
];

export default function Home() {
  return (
    <main className="min-h-screen bg-[#090b0a] text-[#e8eee9]">
      <aside className="fixed left-0 top-0 z-20 hidden h-screen w-[250px] border-r border-white/[0.07] bg-[#0d100e] lg:flex lg:flex-col">
        <div className="flex h-[76px] items-center gap-3 border-b border-white/[0.07] px-6">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[#b8f36b] text-black">
            <ShieldCheck size={22} />
          </div>
          <div>
            <div className="text-[15px] font-bold tracking-tight">Project Doctor</div>
            <div className="text-[10px] tracking-[2px] text-[#849087]">VENOM DEVELOPER TOOLS</div>
          </div>
        </div>

        <div className="px-4 pt-7">
          <div className="mb-3 px-3 text-[10px] font-semibold tracking-[2px] text-[#667169]">WORKSPACE</div>
          <nav className="space-y-1">
            <a href="/" className="flex items-center gap-3 rounded-lg bg-[#b8f36b]/10 px-3 py-3 text-sm font-medium text-[#b8f36b]">
              <LayoutDashboard size={17} /> Overview
            </a>
            <a href="/scanner" className="flex items-center gap-3 rounded-lg px-3 py-3 text-sm text-[#9ba69e] hover:bg-white/[0.04]">
              <ScanSearch size={17} /> Project Scanner
            </a>
            <a href="#checks" className="flex items-center gap-3 rounded-lg px-3 py-3 text-sm text-[#9ba69e] hover:bg-white/[0.04]">
              <ShieldCheck size={17} /> Compatibility Checks
            </a>
            <a href="#issues" className="flex items-center gap-3 rounded-lg px-3 py-3 text-sm text-[#9ba69e] hover:bg-white/[0.04]">
              <TriangleAlert size={17} /> Issues & Reports
            </a>
          </nav>
        </div>

        <div className="mt-9 px-4">
          <div className="mb-3 px-3 text-[10px] font-semibold tracking-[2px] text-[#667169]">DEVELOPMENT</div>
          <nav className="space-y-1">
            <a href="#cli" className="flex items-center gap-3 rounded-lg px-3 py-3 text-sm text-[#9ba69e] hover:bg-white/[0.04]">
              <Terminal size={17} /> CLI Tool
            </a>
            <a href="#settings" className="flex items-center gap-3 rounded-lg px-3 py-3 text-sm text-[#9ba69e] hover:bg-white/[0.04]">
              <Settings size={17} /> Settings
            </a>
          </nav>
        </div>

        <div className="mt-auto p-4">
          <div className="rounded-xl border border-white/[0.07] bg-[#151a16] p-4">
            <div className="mb-2 flex items-center gap-2 text-xs font-semibold text-[#b8f36b]">
              <Zap size={14} /> Built for Venom
            </div>
            <p className="text-xs leading-5 text-[#8b978e]">Developer-focused diagnostics for the Venom ecosystem.</p>
            <a href="https://docs.venom.foundation/" target="_blank" rel="noreferrer" className="mt-3 inline-flex items-center gap-1 text-xs text-[#b8f36b]">
              Official documentation <ArrowUpRight size={13} />
            </a>
          </div>
          <div className="mt-4 flex items-center gap-2 px-2 text-[10px] text-[#68736b]">
            <span className="h-2 w-2 rounded-full bg-[#b8f36b]" /> MVP development
            <span className="ml-auto">v0.1.0</span>
          </div>
        </div>
      </aside>

      <div className="lg:pl-[250px]">
        <header className="flex h-[76px] items-center justify-between border-b border-white/[0.07] px-5 sm:px-9">
          <div>
            <div className="text-xs text-[#78847b]">Workspace / Overview</div>
            <div className="mt-1 text-sm font-semibold">Developer Dashboard</div>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden rounded-full border border-[#b8f36b]/20 bg-[#b8f36b]/[0.07] px-3 py-1.5 text-[11px] text-[#b8f36b] sm:block">
              <span className="mr-2 inline-block h-1.5 w-1.5 rounded-full bg-[#b8f36b]" />
              Venom Ecosystem
            </span>
            <a href="https://github.com/venom-blockchain" target="_blank" rel="noreferrer" className="rounded-lg border border-white/10 p-2 text-[#9ba69e] hover:text-white">
              <Code2 size={17} />
            </a>
          </div>
        </header>

        <div className="mx-auto max-w-[1450px] p-5 sm:p-9">
          <section className="mb-8 flex flex-col justify-between gap-5 md:flex-row md:items-end">
            <div>
              <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-[#b8f36b]/20 bg-[#b8f36b]/[0.06] px-3 py-1.5 text-[10px] font-semibold tracking-wider text-[#b8f36b]">
                <Activity size={12} /> VENOM PROJECT DIAGNOSTICS
              </div>
              <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">Project Doctor<span className="text-[#b8f36b]">.</span></h1>
              <p className="mt-2 max-w-xl text-sm leading-6 text-[#87938a]">
                Find compatibility issues, outdated dependencies and configuration problems in your Venom development projects.
              </p>
            </div>
            <a href="/scanner" className="inline-flex items-center justify-center gap-2 rounded-lg bg-[#b8f36b] px-5 py-3 text-sm font-bold text-[#10150c] transition hover:bg-[#c8ff80]">
              <ScanSearch size={17} /> Scan a project
            </a>
          </section>

          <section className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {[
              { label: "Projects scanned", value: "0", icon: FolderGit2, note: "No scans yet" },
              { label: "Health score", value: "—", icon: Gauge, note: "Awaiting first scan" },
              { label: "Issues detected", value: "—", icon: CircleAlert, note: "No scan data" },
              { label: "Checks available", value: "05", icon: ShieldCheck, note: "Initial check modules" },
            ].map((stat) => (
              <div key={stat.label} className="rounded-xl border border-white/[0.07] bg-[#101411] p-5">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-[#87938a]">{stat.label}</span>
                  <stat.icon size={17} className="text-[#b8f36b]" />
                </div>
                <div className="mt-4 text-3xl font-bold tracking-tight">{stat.value}</div>
                <div className="mt-2 text-[11px] text-[#667169]">{stat.note}</div>
              </div>
            ))}
          </section>

          <section id="scanner" className="mb-6 rounded-xl border border-[#b8f36b]/20 bg-gradient-to-br from-[#151d13] to-[#101411] p-6 sm:p-8">
            <div className="flex flex-col justify-between gap-5 md:flex-row md:items-center">
              <div>
                <div className="mb-3 flex items-center gap-2 text-xs font-semibold text-[#b8f36b]">
                  <ScanSearch size={16} /> START A NEW SCAN
                </div>
                <h2 className="text-xl font-bold">Check your Venom project health</h2>
                <p className="mt-2 max-w-xl text-sm leading-6 text-[#87938a]">
                  Select your local project to scan its dependencies, SDKs and configuration.
                </p>
              </div>
              <div className="flex shrink-0 flex-col gap-2 sm:flex-row">
                <a href="/scanner" className="inline-flex items-center justify-center gap-2 rounded-lg bg-[#b8f36b] px-4 py-3 text-xs font-bold text-black hover:bg-[#c8ff80]">
                  <Terminal size={15} /> Open scanner
                </a>
                <a href="#checks" className="inline-flex items-center justify-center gap-2 rounded-lg border border-white/10 px-4 py-3 text-xs text-white hover:bg-white/5">
                  View checks <ArrowUpRight size={14} />
                </a>
              </div>
            </div>
          </section>

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-5">
            <section id="checks" className="rounded-xl border border-white/[0.07] bg-[#101411] p-5 xl:col-span-3">
              <div className="mb-5 flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-bold">Diagnostic modules</h2>
                  <p className="mt-1 text-xs text-[#77837a]">Available scanning categories</p>
                </div>
                <span className="rounded-md bg-white/[0.05] px-2 py-1 text-[10px] text-[#87938a]">5 MODULES</span>
              </div>
              <div className="divide-y divide-white/[0.06]">
                {checks.map((check) => (
                  <div key={check.name} className="flex items-center gap-3 py-4">
                    <div className="rounded-lg bg-white/[0.04] p-2.5 text-[#b8f36b]"><check.icon size={17} /></div>
                    <div className="min-w-0 flex-1">
                      <div className="text-xs font-semibold">{check.name}</div>
                      <div className="mt-1 text-[11px] text-[#77837a]">{check.detail}</div>
                    </div>
                    <span className={`text-[10px] ${check.status === "Passed" ? "text-[#b8f36b]" : "text-[#89928c]"}`}>
                      {check.status === "Passed" ? <CheckCircle2 size={15} /> : <RefreshCw size={14} />}
                    </span>
                  </div>
                ))}
              </div>
            </section>

            <section id="issues" className="rounded-xl border border-white/[0.07] bg-[#101411] p-5 xl:col-span-2">
              <div className="mb-5">
                <h2 className="text-sm font-bold">Issues & recommendations</h2>
                <p className="mt-1 text-xs text-[#77837a]">Project diagnostic status</p>
              </div>
              <div className="space-y-3">
                {issues.map((issue) => (
                  <div key={issue.title} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-4">
                    <div className={`mb-2 flex items-center gap-2 text-[10px] font-semibold ${issue.color === "warning" ? "text-[#e9bc66]" : "text-[#82b6e8]"}`}>
                      {issue.color === "warning" ? <TriangleAlert size={13} /> : <CircleAlert size={13} />}
                      {issue.severity}
                    </div>
                    <div className="text-xs font-semibold">{issue.title}</div>
                    <p className="mt-1 text-[11px] leading-5 text-[#77837a]">{issue.description}</p>
                  </div>
                ))}
              </div>
            </section>
          </div>

          <section id="cli" className="mt-6 rounded-xl border border-white/[0.07] bg-[#101411] p-5 sm:p-6">
            <div className="mb-4 flex items-center gap-2">
              <Terminal size={17} className="text-[#b8f36b]" />
              <h2 className="text-sm font-bold">CLI quick start</h2>
              <span className="rounded bg-white/[0.05] px-2 py-1 text-[9px] text-[#87938a]">COMING SOON</span>
            </div>
            <p className="mb-4 text-xs text-[#87938a]">The planned CLI workflow will let developers scan projects directly from their terminal.</p>
            <div className="overflow-x-auto rounded-lg border border-white/[0.06] bg-[#090b0a] p-4 font-mono text-xs leading-7">
              <div className="text-[#68766c]"># Install the CLI (planned)</div>
              <div><span className="text-[#b8f36b]">$</span> npm install -g venom-project-doctor</div>
              <div className="mt-2 text-[#68766c]"># Scan your project (planned)</div>
              <div><span className="text-[#b8f36b]">$</span> venom-doctor scan .</div>
            </div>
          </section>

          <footer className="mt-10 flex flex-col justify-between gap-3 border-t border-white/[0.07] pt-5 text-[10px] text-[#667169] sm:flex-row">
            <span>VENOM PROJECT DOCTOR · OPEN-SOURCE DEVELOPER TOOL</span>
            <span>Prototype v0.1.0 · Not yet connected to the scanning engine</span>
          </footer>
        </div>
      </div>
    </main>
  );
}
