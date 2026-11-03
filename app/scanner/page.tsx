
"use client";

import { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowLeft,
  CheckCircle2,
  CircleAlert,
  Copy,
  Download,
  FolderOpen,
  Info,
  Loader2,
  ShieldCheck,
  TriangleAlert,
  Upload,
  Wrench,
  Check,
} from "lucide-react";
import Link from "next/link";
import JSZip from "jszip";

type Issue = {
  severity: "error" | "warning" | "info";
  category: string;
  title: string;
  message: string;
  file?: string;
};

type Report = {
  projectName: string;
  projectType: string;
  healthScore: number;
  summary: {
    totalChecks: number;
    passed: number;
    warnings: number;
    errors: number;
  };
  tools: { name: string; version: string }[];
  checks: {
    name: string;
    status: "passed" | "warning" | "failed";
    message: string;
  }[];
  issues: Issue[];
  scannedAt: string;
};

type FixSuggestion = {
  explanation: string;
  steps: string[];
  code?: string;
  codeLabel?: string;
  caution?: string;
};

const ignored = [
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  "coverage",
  ".turbo",
  ".vercel",
];

function getFixSuggestion(issue: Issue): FixSuggestion {
  const title = issue.title.toLowerCase();

  if (title.includes("nekoton")) {
    return {
      explanation:
        "The scanner did not find the documented Locklift Nekoton WASM override. This override may be required by the Locklift setup you are using.",
      steps: [
        "Open the root package.json file.",
        "Check whether it already contains an overrides section.",
        "Add the Nekoton override shown below, merging it with existing overrides if necessary.",
        "Save package.json and run npm install.",
        "Run the project scan again.",
      ],
      code: `"overrides": {
  "nekoton-wasm": "npm:nekoton-wasm-locklift@^1.20.2"
}`,
      codeLabel: "package.json override fragment",
      caution:
        "This is the documented rule currently implemented in this scanner. Verify that it applies to your installed Locklift version before changing an existing project.",
    };
  }

  if (title.includes("compatibility unverified")) {
    return {
      explanation:
        "The scanner recognized this SDK package but does not yet have a maintained compatibility matrix to confirm whether its installed version is compatible.",
      steps: [
        "Check the installed package version in package.json.",
        "Review the official documentation and release notes for that package.",
        "Check its compatibility requirements against your Locklift and compiler versions.",
        "Run your project's build and tests after any version change.",
      ],
      code: "npm ls locklift nekoton-wasm @eversdk/core",
      codeLabel: "Command to inspect installed SDK versions",
      caution:
        "This is an unverified status, not proof that your SDK version is incompatible. Do not upgrade or downgrade packages solely to remove this warning.",
    };
  }

  if (title.includes("configuration missing")) {
    return {
      explanation:
        "Locklift is listed as a dependency, but the scanner could not find a recognized Locklift configuration file.",
      steps: [
        "Check whether locklift.config.ts or locklift.config.js exists in your project.",
        "If it is missing, create a configuration using the official Locklift documentation for your installed version.",
        "Configure the compiler and network settings required by your project.",
        "Run the scan again.",
      ],
      caution:
        "Do not copy a configuration from an unrelated project without checking its network, compiler, and key settings.",
    };
  }

  if (
    title.includes("tooling not detected") ||
    title.includes("sdk not detected")
  ) {
    return {
      explanation:
        "The scanner did not recognize any supported Venom ecosystem packages in the project manifest.",
      steps: [
        "Check that you selected the correct project folder.",
        "Open its root package.json file.",
        "Check whether the project uses Locklift or another supported SDK.",
        "If this is a Venom project, consult the official developer documentation for the appropriate dependencies.",
        "Run the scan again.",
      ],
      caution:
        "A project can use other tools or workflows that this scanner does not recognize yet.",
    };
  }

  if (title.includes("invalid package.json")) {
    return {
      explanation:
        "The package.json file could not be parsed as valid JSON.",
      steps: [
        "Open the reported package.json file.",
        "Check for missing commas, extra commas, unmatched braces, or invalid quotation marks.",
        "Validate the JSON and save the file.",
        "Run the scan again.",
      ],
      caution:
        "Keep a backup before editing an existing project manifest.",
    };
  }

  if (title.includes("package.json not found")) {
    return {
      explanation:
        "No package.json file was found in the selected project files.",
      steps: [
        "Check that you selected the project root folder.",
        "If the project uses Node.js, create or restore its package.json file.",
        "If the project does not use Node.js, check whether its development workflow is supported by this scanner.",
      ],
    };
  }

  return {
    explanation:
      "The scanner found an issue that needs further inspection.",
    steps: [
      issue.file
        ? `Inspect the reported file: ${issue.file}`
        : "Review the issue and the related project configuration.",
      "Check the relevant official developer documentation.",
      "Make the required change only after verifying that it applies to your project.",
      "Run the scan again.",
    ],
    caution:
      "This is a general recommendation. The scanner has not verified an automatic fix for this issue.",
  };
}

export default function ScannerPage() {
  const inputRef = useRef<HTMLInputElement>(null);
const zipInputRef = useRef<HTMLInputElement>(null);

  const [files, setFiles] = useState<File[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [report, setReport] = useState<Report | null>(null);
  const [copied, setCopied] = useState("");

  useEffect(() => {
    inputRef.current?.setAttribute("webkitdirectory", "");
    inputRef.current?.setAttribute("directory", "");
  }, []);

  const chooseFolder = () => {
    setError("");
    inputRef.current?.click();
  };
const handleFiles = (selected: FileList | null) => {
  if (!selected) return;

  const all = Array.from(selected);

  const eligible = all.filter((file) => {
    const path =
      (file as File & { webkitRelativePath?: string })
        .webkitRelativePath || file.name;

    const parts = path.split("/");
    const filename = parts[parts.length - 1];

    if (parts.some((part) => ignored.includes(part))) return false;
    if (filename.startsWith(".env")) return false;
    if (filename === ".npmrc" || filename === ".pypirc") return false;
    if (filename === "id_rsa" || filename === "id_ed25519") return false;

    return (
      filename === "package.json" ||
      /^locklift\.config\.(ts|js|cjs|mjs)$/.test(filename) ||
      /\.(sol|t\.sol|leo|json|ts|js|cjs|mjs)$/.test(filename)
    );
  });

  if (eligible.length === 0) {
    setFiles([]);
    setError(
      "No supported project files found. Select a project containing package.json or smart contract files."
    );
    return;
  }

  if (eligible.length > 500) {
    setFiles([]);
    setError("The selected project contains too many supported files. Maximum: 500.");
    return;
  }

  const totalSize = eligible.reduce((sum, file) => sum + file.size, 0);

  if (totalSize > 5 * 1024 * 1024) {
    setFiles([]);
    setError(
      "Supported project files exceed the 5 MB scanning limit. Select a smaller project."
    );
    return;
  }

  setFiles(eligible);
  setReport(null);
  setError("");
  setCopied("");
};
  const handleZipUpload = async (selected: File | null) => {
  if (!selected) return;

  setLoading(true);
  setError("");
  setFiles([]);
  setReport(null);

  try {
    if (!selected.name.toLowerCase().endsWith(".zip")) {
      throw new Error("Please select a valid ZIP file.");
    }

    if (selected.size > 10 * 1024 * 1024) {
      throw new Error("ZIP file is too large. Maximum upload size is 10 MB.");
    }

    const zip = await JSZip.loadAsync(selected);
    const entries = Object.entries(zip.files);

    if (entries.length > 2000) {
      throw new Error("ZIP contains too many entries. Maximum: 2,000.");
    }

    const extractedFiles: File[] = [];
    let totalBytes = 0;

    for (const [originalPath, entry] of entries) {
      if (entry.dir) continue;

      const path = originalPath.replace(/\\/g, "/");
      const parts = path.split("/");
      const filename = parts[parts.length - 1];

      // Reject unsafe paths.
      if (
        path.startsWith("/") ||
        parts.some((part) => part === ".." || part === ".")
      ) {
        continue;
      }

      // Exclude unnecessary and sensitive files.
      if (
        parts.some((part) => ignored.includes(part)) ||
        filename.startsWith(".env") ||
        [".npmrc", ".pypirc", "id_rsa", "id_ed25519"].includes(filename)
      ) {
        continue;
      }

      // Keep only files supported by the scanner.
      const supported =
        filename === "package.json" ||
        /^locklift\.config\.(ts|js|cjs|mjs)$/.test(filename) ||
        /\.(sol|t\.sol|leo|json|ts|js|cjs|mjs)$/.test(filename);

      if (!supported) continue;

      // Check declared uncompressed size before extracting.
      const metadata = entry as typeof entry & {
        _data?: { uncompressedSize?: number };
      };

      const declaredSize = metadata._data?.uncompressedSize;

      if (
        typeof declaredSize === "number" &&
        totalBytes + declaredSize > 5 * 1024 * 1024
      ) {
        throw new Error("Extracted project files exceed the 5 MB limit.");
      }

      const content = await entry.async("arraybuffer");

      totalBytes += content.byteLength;

      if (totalBytes > 5 * 1024 * 1024) {
        throw new Error("Extracted project files exceed the 5 MB limit.");
      }

      if (extractedFiles.length >= 500) {
        throw new Error("Maximum 500 supported project files allowed.");
      }

      const projectFile = new File([content], filename, {
        type: "text/plain",
      });

      Object.defineProperty(projectFile, "relativePath", {
        value: path,
      });

      extractedFiles.push(projectFile);
    }

    if (extractedFiles.length === 0) {
      throw new Error(
        "No supported project files found in this ZIP archive."
      );
    }

    setFiles(extractedFiles);
    setCopied("");
  } catch (err) {
    setFiles([]);
    setError(
      err instanceof Error
        ? err.message
        : "Unable to extract the ZIP file."
    );
  } finally {
    setLoading(false);
  }
};

const scanProject = async () => {
    if (!files.length) {
      setError("Please select a project folder first.");
      return;
    }

    setLoading(true);
    setError("");
    setReport(null);

    try {
      const projectFiles = await Promise.all(
        files.map(async (file) => ({
          path:
  (file as File & {
    webkitRelativePath?: string;
    relativePath?: string;
  }).webkitRelativePath ||
  (file as File & { relativePath?: string }).relativePath ||
  file.name,
          content: await file.text(),
        }))
      );

      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ files: projectFiles }),
      });

      const result = await response.json();

      if (!response.ok || !result.success) {
        throw new Error(result.error || "Project scan failed.");
      }

      setReport(result.report);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Unable to scan project."
      );
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = () => {
    if (!report) return;

    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = `${report.projectName.replace(
      /[^a-z0-9-_]/gi,
      "-"
    )}-report.json`;

    link.click();
    URL.revokeObjectURL(url);
  };

  const copyFix = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(id);
    } catch {
      setError(
        "Clipboard access failed. Please select and copy the code manually."
      );
    }
  };

  return (
    <main className="min-h-screen bg-[#090b0a] px-5 py-8 text-[#e8eee9] sm:px-10">
      <div className="mx-auto max-w-5xl">
        <Link
          href="/"
          className="mb-9 inline-flex items-center gap-2 text-sm text-[#87938a] hover:text-[#b8f36b]"
        >
          <ArrowLeft size={16} /> Back to dashboard
        </Link>

        <div className="mb-8">
          <div className="mb-3 flex items-center gap-2 text-xs font-semibold tracking-wider text-[#b8f36b]">
            <Activity size={15} /> VENOM PROJECT DIAGNOSTICS
          </div>

          <h1 className="text-3xl font-bold sm:text-4xl">
            Project Scanner<span className="text-[#b8f36b]">.</span>
          </h1>

          <p className="mt-3 max-w-2xl text-sm leading-6 text-[#87938a]">
            Select your local project folder to inspect SDK dependencies,
            Locklift configuration and smart contract files.
          </p>
        </div>

        <input
          ref={inputRef}
          type="file"
          multiple
          className="hidden"
          onChange={(event) => handleFiles(event.target.files)}
        />

        <section className="rounded-2xl border border-white/[0.08] bg-[#101411] p-6 sm:p-9">
          <div className="mb-5 flex items-center gap-3">
            <div className="rounded-xl bg-[#b8f36b]/10 p-3 text-[#b8f36b]">
              <FolderOpen size={23} />
            </div>
            <div>
              <h2 className="font-semibold">Select project folder</h2>
              <p className="mt-1 text-xs text-[#87938a]">
                Choose a local project to begin diagnostics.
              </p>
            </div>
          </div>

          <button
            onClick={chooseFolder}
            disabled={loading}
            className="flex w-full flex-col items-center justify-center rounded-xl border border-dashed border-[#b8f36b]/30 bg-[#b8f36b]/[0.035] px-5 py-12 text-center transition hover:border-[#b8f36b]/70 hover:bg-[#b8f36b]/[0.07] disabled:opacity-50"
          >
            <Upload size={29} className="mb-4 text-[#b8f36b]" />
            <span className="text-sm font-semibold">Choose project folder</span>
            <span className="mt-2 text-xs text-[#87938a]">
              Select a local folder containing your project files
            </span>
          </button>
<input
  ref={zipInputRef}
  type="file"
  accept=".zip,application/zip"
  className="hidden"
  disabled={loading}
  onChange={(event) => {
    handleZipUpload(event.target.files?.[0] || null);
    event.target.value = "";
  }}
/>

<button
  type="button"
  onClick={() => zipInputRef.current?.click()}
  disabled={loading}
  className="mt-3 flex w-full items-center justify-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-5 py-4 text-sm font-semibold text-[#e8eee9] transition hover:border-[#b8f36b]/50 hover:bg-white/[0.05] disabled:opacity-50"
>
  <Upload size={17} className="text-[#b8f36b]" />
  Upload project ZIP
</button>
          <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
            <span className="text-xs text-[#87938a]">
              {files.length
                ? `${files.length} supported files selected`
                : "No project selected"}
            </span>

            {files.length > 0 && (
              <button
                onClick={() => {
                  setFiles([]);
                  setReport(null);
                  setError("");
                  setCopied("");
                }}
                className="text-xs text-[#b8f36b] hover:underline"
              >
                Clear selection
              </button>
            )}
          </div>

          <button
            onClick={scanProject}
            disabled={!files.length || loading}
            className="mt-6 flex w-full items-center justify-center gap-2 rounded-lg bg-[#b8f36b] px-5 py-3.5 text-sm font-bold text-[#10150c] transition hover:bg-[#c8ff80] disabled:cursor-not-allowed disabled:opacity-40"
          >
            {loading ? (
              <>
                <Loader2 size={17} className="animate-spin" />
                Scanning project...
              </>
            ) : (
              <>
                <ShieldCheck size={17} /> Run project scan
              </>
            )}
          </button>

          <p className="mt-4 text-center text-[11px] leading-5 text-[#667169]">
            Read-only scanning · .env and dependency folders excluded ·
            Maximum 500 files and 5 MB
          </p>
        </section>

        {error && (
          <div className="mt-5 rounded-lg border border-red-500/20 bg-red-500/[0.06] p-4 text-sm text-red-300">
            {error}
          </div>
        )}

        {report && (
          <section className="mt-8 space-y-5">
            <div className="rounded-xl border border-[#b8f36b]/20 bg-[#101711] p-6">
              <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
                <div>
                  <div className="text-xs text-[#87938a]">SCAN REPORT</div>
                  <h2 className="mt-2 text-xl font-bold">
                    {report.projectName}
                  </h2>
                  <p className="mt-1 text-xs text-[#87938a]">
                    {report.projectType}
                  </p>
                </div>

                <button
                  onClick={downloadReport}
                  className="flex items-center justify-center gap-2 rounded-lg border border-white/10 px-4 py-2.5 text-xs hover:bg-white/5"
                >
                  <Download size={15} /> Download JSON
                </button>
              </div>

              <div className="mt-7 grid grid-cols-2 gap-4 sm:grid-cols-4">
                <div>
                  <div className="text-3xl font-bold text-[#b8f36b]">
                    {report.healthScore}%
                  </div>
                  <div className="mt-1 text-xs text-[#87938a]">
                    Preliminary score
                  </div>
                </div>
                <div>
                  <div className="text-3xl font-bold">
                    {report.summary.passed}
                  </div>
                  <div className="mt-1 text-xs text-[#87938a]">Passed</div>
                </div>
                <div>
                  <div className="text-3xl font-bold text-amber-400">
                    {report.summary.warnings}
                  </div>
                  <div className="mt-1 text-xs text-[#87938a]">Warnings</div>
                </div>
                <div>
                  <div className="text-3xl font-bold text-red-400">
                    {report.summary.errors}
                  </div>
                  <div className="mt-1 text-xs text-[#87938a]">Errors</div>
                </div>
              </div>

              <p className="mt-5 text-[11px] text-[#667169]">
                A structural diagnostic score, not a security audit or proof
                of SDK compatibility.
              </p>
            </div>

            <div className="rounded-xl border border-white/[0.08] bg-[#101411] p-6">
              <h3 className="mb-4 font-semibold">Diagnostic checks</h3>
              <div className="divide-y divide-white/[0.06]">
                {report.checks.map((check, index) => (
                  <div key={index} className="flex items-start gap-3 py-4">
                    {check.status === "passed" ? (
                      <CheckCircle2
                        className="mt-0.5 text-[#b8f36b]"
                        size={17}
                      />
                    ) : check.status === "failed" ? (
                      <CircleAlert
                        className="mt-0.5 text-red-400"
                        size={17}
                      />
                    ) : (
                      <TriangleAlert
                        className="mt-0.5 text-amber-400"
                        size={17}
                      />
                    )}
                    <div>
                      <div className="text-sm font-medium">{check.name}</div>
                      <div className="mt-1 text-xs leading-5 text-[#87938a]">
                        {check.message}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-xl border border-white/[0.08] bg-[#101411] p-6">
              <h3 className="mb-4 font-semibold">Detected SDK packages</h3>
              {report.tools.length ? (
                <div className="space-y-3">
                  {report.tools.map((tool) => (
                    <div
                      key={tool.name}
                      className="flex justify-between gap-3 rounded-lg bg-white/[0.03] p-3 text-sm"
                    >
                      <span>{tool.name}</span>
                      <span className="font-mono text-xs text-[#b8f36b]">
                        {tool.version}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-[#87938a]">
                  No recognized SDK packages found.
                </p>
              )}
            </div>

            <div className="rounded-xl border border-[#b8f36b]/20 bg-[#101711] p-6">
              <div className="mb-5 flex items-center gap-3">
                <div className="rounded-lg bg-[#b8f36b]/10 p-2 text-[#b8f36b]">
                  <Wrench size={19} />
                </div>
                <div>
                  <h3 className="font-semibold">Fix Suggestions</h3>
                  <p className="mt-1 text-xs text-[#87938a]">
                    Guidance based on the issues detected in this scan.
                  </p>
                </div>
              </div>

              {report.issues.length ? (
                <div className="space-y-4">
                  {report.issues.map((issue, index) => {
                    const fix = getFixSuggestion(issue);
                    const id = `fix-${index}`;

                    return (
                      <div
                        key={`${issue.title}-${index}`}
                        className="rounded-xl border border-white/[0.08] bg-[#0c100d] p-4 sm:p-5"
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`rounded-md px-2 py-1 text-[10px] font-bold uppercase ${
                              issue.severity === "error"
                                ? "bg-red-500/10 text-red-400"
                                : issue.severity === "warning"
                                  ? "bg-amber-500/10 text-amber-400"
                                  : "bg-blue-500/10 text-blue-400"
                            }`}
                          >
                            {issue.severity}
                          </span>
                          <span className="text-[10px] text-[#87938a]">
                            {issue.category}
                          </span>
                        </div>

                        <h4 className="mt-3 text-sm font-semibold">
                          {issue.title}
                        </h4>
                        <p className="mt-2 text-xs leading-5 text-[#87938a]">
                          {issue.message}
                        </p>

                        {issue.file && (
                          <p className="mt-2 text-xs text-[#b8f36b]">
                            File: {issue.file}
                          </p>
                        )}

                        <div className="mt-4 border-t border-white/[0.07] pt-4">
                          <div className="flex items-center gap-2 text-xs font-semibold text-[#b8f36b]">
                            <Wrench size={14} /> Recommended solution
                          </div>

                          <p className="mt-2 text-xs leading-5 text-[#aab5ad]">
                            {fix.explanation}
                          </p>

                          <ol className="mt-3 list-decimal space-y-2 pl-5 text-xs leading-5 text-[#aab5ad]">
                            {fix.steps.map((step, stepIndex) => (
                              <li key={stepIndex}>{step}</li>
                            ))}
                          </ol>

                          {fix.code && (
                            <div className="mt-4 overflow-hidden rounded-lg border border-white/[0.08]">
                              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.08] bg-white/[0.03] px-3 py-2">
                                <span className="text-[11px] text-[#87938a]">
                                  {fix.codeLabel || "Suggested code"}
                                </span>
                                <button
                                  onClick={() => copyFix(fix.code!, id)}
                                  className="flex items-center gap-1.5 rounded-md border border-white/10 px-2.5 py-1.5 text-[11px] hover:bg-white/[0.06]"
                                >
                                  {copied === id ? (
                                    <>
                                      <Check size={13} className="text-[#b8f36b]" />
                                      Copied
                                    </>
                                  ) : (
                                    <>
                                      <Copy size={13} /> Copy Fix
                                    </>
                                  )}
                                </button>
                              </div>
                              <pre className="overflow-x-auto p-4 text-xs leading-6 text-[#b8f36b]">
                                <code>{fix.code}</code>
                              </pre>
                            </div>
                          )}

                          {fix.caution && (
                            <div className="mt-4 flex items-start gap-2 rounded-lg border border-amber-500/15 bg-amber-500/[0.05] p-3">
                              <Info
                                size={15}
                                className="mt-0.5 shrink-0 text-amber-400"
                              />
                              <p className="text-[11px] leading-5 text-[#b9b2a0]">
                                {fix.caution}
                              </p>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="rounded-lg border border-[#b8f36b]/15 bg-[#b8f36b]/[0.04] p-4 text-sm text-[#b8f36b]">
                  No issues were reported by the current checks. Keep testing
                  your project and review the compatibility checks above.
                </div>
              )}

              <p className="mt-5 flex items-start gap-2 text-[11px] leading-5 text-[#667169]">
                <Info size={14} className="mt-0.5 shrink-0" />
                Suggestions are guidance, not automatic changes. Always verify
                them against your project's requirements and official
                documentation.
              </p>
            </div>

            <div className="rounded-xl border border-white/[0.08] bg-[#101411] p-6">
              <h3 className="mb-3 font-semibold">Scan information</h3>
              <p className="text-xs text-[#87938a]">
                Scanned at: {new Date(report.scannedAt).toLocaleString()}
              </p>
            </div>
          </section>
        )}
      </div>
    </main>
  );
}
