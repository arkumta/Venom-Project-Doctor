
"use client";

import { useEffect, useRef, useState } from "react";
import ContractGuardPanel, {
  type ContractSecurityReport,
} from "@/components/ContractGuardPanel";
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

type SecuritySeverity =
  | "critical"
  | "high"
  | "moderate"
  | "low"
  | "info"
  | "unknown";

type SecurityVulnerability = {
  id: string;
  name: string;
  version: string;
  severity: "critical" | "high" | "moderate" | "low" | "unknown";
  isDirect: boolean;
  summary: string;
  affectedRange: string;
  fixedVersions: string[];
  advisoryUrl: string | null;
  locations: string[];
  remediation: string;
  nearestNestedPackage: string | null;
  dependencyChain: string[];
  suggestedCommand: string | null;
  upgradeRisk: "patch" | "minor" | "major" | "unknown";
};

type SecurityAuditReport = {
  status: "completed" | "skipped" | "unavailable";
  message: string;
  summary: {
    total: number;
    critical: number;
    high: number;
    moderate: number;
    low: number;
    info: number;
  };
  vulnerabilities: SecurityVulnerability[];
  scannedPackages: number;
};

type FixSuggestion = {
  explanation: string;
  steps: string[];
  code?: string;
  codeLabel?: string;
  caution?: string;
};

type SecurityComparison = {
  previousScannedAt: string;
  currentScannedAt: string;
  noLongerDetected: SecurityVulnerability[];
  stillDetected: SecurityVulnerability[];
  newlyDetected: SecurityVulnerability[];
};

type SavedScan = {
  id: string;
  projectName: string;
  report: Report;
  securityReport: SecurityAuditReport | null;
  contractSecurityReport?: ContractSecurityReport | null;
  savedAt: string;
};

const SCAN_HISTORY_KEY = "venom-project-doctor-scan-history-v1";
const MAX_SAVED_SCANS = 30;

function compareSecurityReports(
  previous: SecurityAuditReport,
  current: SecurityAuditReport,
  previousScannedAt: string,
  currentScannedAt: string
): SecurityComparison {
  const getKey = (item: SecurityVulnerability) =>
    `${item.id.trim().toLowerCase()}::${item.name.trim().toLowerCase()}`;

  const previousMap = new Map(
    previous.vulnerabilities.map((item) => [getKey(item), item])
  );

  const currentMap = new Map(
    current.vulnerabilities.map((item) => [getKey(item), item])
  );

  return {
    previousScannedAt,
    currentScannedAt,
    noLongerDetected: [...previousMap.entries()]
      .filter(([key]) => !currentMap.has(key))
      .map(([, item]) => item),
    stillDetected: [...currentMap.entries()]
      .filter(([key]) => previousMap.has(key))
      .map(([, item]) => item),
    newlyDetected: [...currentMap.entries()]
      .filter(([key]) => !previousMap.has(key))
      .map(([, item]) => item),
  };
}

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
  const [githubRepositoryUrl, setGithubRepositoryUrl] = useState("");

  const [securityReport, setSecurityReport] =
    useState<SecurityAuditReport | null>(null);

    const [contractSecurityReport, setContractSecurityReport] =
  useState<ContractSecurityReport | null>(null);
  const [previousSecurityReport, setPreviousSecurityReport] =
    useState<SecurityAuditReport | null>(null);

  const [previousProjectName, setPreviousProjectName] = useState("");
  const [previousScanAt, setPreviousScanAt] = useState("");

  const [securityComparison, setSecurityComparison] =
    useState<SecurityComparison | null>(null);

  const [files, setFiles] = useState<File[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [report, setReport] = useState<Report | null>(null);
  const [copied, setCopied] = useState("");

  const [scanHistory, setScanHistory] = useState<SavedScan[]>([]);
  const [historyReady, setHistoryReady] = useState(false);
  const [compareFirstId, setCompareFirstId] = useState("");
  const [compareSecondId, setCompareSecondId] = useState("");

  useEffect(() => {
    inputRef.current?.setAttribute("webkitdirectory", "");
    inputRef.current?.setAttribute("directory", "");

    try {
      const saved = localStorage.getItem(SCAN_HISTORY_KEY);

      if (saved) {
        const parsed: unknown = JSON.parse(saved);

        if (Array.isArray(parsed)) {
          setScanHistory(parsed as SavedScan[]);
        }
      }
    } catch {
      // Keep the scanner usable if browser storage contains invalid data.
    } finally {
      setHistoryReady(true);
    }
  }, []);

  const persistHistory = (nextHistory: SavedScan[]) => {
    setScanHistory(nextHistory);

    try {
      localStorage.setItem(
        SCAN_HISTORY_KEY,
        JSON.stringify(nextHistory)
      );
    } catch {
      setError(
        "Scan completed, but browser storage is full. Delete older history records."
      );
    }
  };

  const deleteHistoryItem = (id: string) => {
    persistHistory(scanHistory.filter((item) => item.id !== id));

    if (compareFirstId === id) setCompareFirstId("");
    if (compareSecondId === id) setCompareSecondId("");
  };

  const downloadHistoryItem = (item: SavedScan) => {
    const blob = new Blob(
      [
        JSON.stringify(
          {
            report: item.report,
            securityReport: item.securityReport,
            contractSecurityReport: item.contractSecurityReport ?? null,
          },
          null,
          2
        ),
      ],
      { type: "application/json" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = `${item.projectName.replace(
      /[^a-z0-9-_]/gi,
      "-"
    )}-scan.json`;

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
  };

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
      setError(
        "The selected project contains too many supported files. Maximum: 500."
      );
      return;
    }

    const totalSize = eligible.reduce(
      (sum, file) => sum + file.size,
      0
    );

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
        throw new Error(
          "ZIP file is too large. Maximum upload size is 10 MB."
        );
      }

      const zip = await JSZip.loadAsync(selected);
      const entries = Object.entries(zip.files);

      if (entries.length > 2000) {
        throw new Error(
          "ZIP contains too many entries. Maximum: 2,000."
        );
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
          throw new Error(
            "Extracted project files exceed the 5 MB limit."
          );
        }

        const content = await entry.async("arraybuffer");

        totalBytes += content.byteLength;

        if (totalBytes > 5 * 1024 * 1024) {
          throw new Error(
            "Extracted project files exceed the 5 MB limit."
          );
        }

        if (extractedFiles.length >= 500) {
          throw new Error(
            "Maximum 500 supported project files allowed."
          );
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
    setSecurityReport(null);
    setContractSecurityReport(null);

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

      const nextSecurityReport = result.securityReport ?? null;
      const nextContractSecurityReport =
  result.contractSecurityReport ?? null;
      const nextProjectName = result.report.projectName as string;
      const nextScannedAt = result.report.scannedAt as string;

      if (nextSecurityReport?.status === "completed") {
        if (
          previousSecurityReport?.status === "completed" &&
          previousProjectName === nextProjectName
        ) {
          setSecurityComparison(
            compareSecurityReports(
              previousSecurityReport,
              nextSecurityReport,
              previousScanAt,
              nextScannedAt
            )
          );
        } else {
          setSecurityComparison(null);
        }

        setPreviousSecurityReport(nextSecurityReport);
        setPreviousProjectName(nextProjectName);
        setPreviousScanAt(nextScannedAt);
      } else {
        setSecurityComparison(null);
      }

      setReport(result.report);
      setSecurityReport(nextSecurityReport);
      setContractSecurityReport(nextContractSecurityReport);

      // Save the successful scan without storing uploaded source files.
const savedScan: SavedScan = {
  id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
  projectName: nextProjectName,
  report: result.report,
  securityReport: nextSecurityReport,
  contractSecurityReport: nextContractSecurityReport,
  savedAt: new Date().toISOString(),
};

      persistHistory(
        [savedScan, ...scanHistory].slice(0, MAX_SAVED_SCANS)
      );
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Unable to scan project."
      );
    } finally {
      setLoading(false);
    }
  };
const scanGitHubRepository = async () => {
  if (!githubRepositoryUrl.trim()) {
    setError("Please enter a GitHub repository URL.");
    return;
  }

  setLoading(true);
  setError("");
  setReport(null);
  setSecurityReport(null);
  setContractSecurityReport(null);
  setSecurityComparison(null);

  try {
    const response = await fetch("/api/github-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        repositoryUrl: githubRepositoryUrl.trim(),
      }),
    });

    const result = await response.json();

    if (!response.ok || !result.success) {
      throw new Error(result.error || "GitHub repository scan failed.");
    }

    const nextReport = {
      ...result.report,
      projectName: result.repository.name,
    };

    const nextSecurityReport = result.securityReport ?? null;
    const nextContractSecurityReport =
      result.contractSecurityReport ?? null;

    setReport(nextReport);
    setSecurityReport(nextSecurityReport);
    setContractSecurityReport(nextContractSecurityReport);

    const savedScan: SavedScan = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      projectName: nextReport.projectName,
      report: nextReport,
      securityReport: nextSecurityReport,
      contractSecurityReport: nextContractSecurityReport,
      savedAt: new Date().toISOString(),
    };

    persistHistory(
      [savedScan, ...scanHistory].slice(0, MAX_SAVED_SCANS)
    );
  } catch (err) {
    setError(
      err instanceof Error
        ? err.message
        : "Unable to scan GitHub repository."
    );
  } finally {
    setLoading(false);
  }
};
  const downloadReport = () => {
    if (!report) return;

const fullReport = {
  report,
  securityReport,
  contractSecurityReport,
  securityComparison,
};

    const blob = new Blob(
      [JSON.stringify(fullReport, null, 2)],
      { type: "application/json" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = `${report.projectName.replace(
      /[^a-z0-9-_]/gi,
      "-"
    )}-full-report.json`;

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
  };

  const downloadPdfReport = () => {
    if (!report) return;

    // Open the print window directly from the button click so popup blockers
    // are less likely to block it.
    const printWindow = window.open("", "_blank");

    if (!printWindow) {
      setError("Your browser blocked the PDF report window. Allow pop-ups and try again.");
      return;
    }

    const escapeHtml = (value: unknown) =>
      String(value ?? "").replace(/[&<>\"']/g, (character) => {
        const entities: Record<string, string> = {
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        };
        return entities[character];
      });

    const severityRows = [
      ["Critical", securityReport?.summary.critical ?? 0],
      ["High", securityReport?.summary.high ?? 0],
      ["Moderate", securityReport?.summary.moderate ?? 0],
      ["Low", securityReport?.summary.low ?? 0],
      ["Informational", securityReport?.summary.info ?? 0],
    ];
const contractFindingsHtml =
  contractSecurityReport?.findings.length
    ? contractSecurityReport.findings.map((item) => `
        <article class="finding">
          <h3>${escapeHtml(item.title)}</h3>
          <p><strong>Severity:</strong> ${escapeHtml(item.severity.toUpperCase())}</p>
          <p><strong>Confidence:</strong> ${escapeHtml(item.confidence)}</p>
          <p><strong>Category:</strong> ${escapeHtml(item.category)}</p>
          <p><strong>Location:</strong> ${escapeHtml(item.file)} : ${item.line}</p>
          <p>${escapeHtml(item.description)}</p>
          <p><strong>Recommendation:</strong> ${escapeHtml(item.recommendation)}</p>
          <p class="note">Manual review required.</p>
        </article>
      `).join("")
    : "<p>No ContractGuard findings were reported, or contract scanning was skipped.</p>";

const contractGuardHtml = `
  <section>
    <h2>ContractGuard — Smart Contract Security</h2>
    <p>${escapeHtml(contractSecurityReport?.message ?? "No ContractGuard report available.")}</p>
    <div class="metrics">
      <div class="metric"><strong>${contractSecurityReport?.summary.filesScanned ?? 0}</strong><span>Files scanned</span></div>
      <div class="metric"><strong>${contractSecurityReport?.summary.total ?? 0}</strong><span>Findings</span></div>
      <div class="metric"><strong>${contractSecurityReport?.summary.critical ?? 0}</strong><span>Critical</span></div>
      <div class="metric"><strong>${contractSecurityReport?.summary.high ?? 0}</strong><span>High</span></div>
      <div class="metric"><strong>${contractSecurityReport?.summary.medium ?? 0}</strong><span>Medium</span></div>
      <div class="metric"><strong>${contractSecurityReport?.summary.low ?? 0}</strong><span>Low</span></div>
    </div>
    ${contractFindingsHtml}
    <h3>ContractGuard limitations</h3>
    <ul>
      ${(contractSecurityReport?.limitations ?? []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
    </ul>
  </section>
`;
    const vulnerabilityHtml =
      securityReport?.status === "completed" &&
      securityReport.vulnerabilities.length > 0
        ? securityReport.vulnerabilities
            .map(
              (item) => `
                <article class="finding">
                  <div class="finding-header">
                    <h3>${escapeHtml(item.name)} <span class="version">v${escapeHtml(item.version)}</span></h3>
                    <span class="severity ${escapeHtml(item.severity)}">${escapeHtml(item.severity.toUpperCase())}</span>
                  </div>
                  <p><strong>Advisory:</strong> ${escapeHtml(item.id)}</p>
                  <p><strong>Dependency type:</strong> ${item.isDirect ? "Direct" : "Transitive"}</p>
                  <p><strong>Affected range:</strong> ${escapeHtml(item.affectedRange || "Not specified")}</p>
                  <p><strong>Summary:</strong> ${escapeHtml(item.summary || "No summary supplied.")}</p>
                  <p><strong>Remediation:</strong> ${escapeHtml(item.remediation || "Review the advisory and package maintainer guidance.")}</p>
                  ${item.fixedVersions.length ? `<p><strong>Fixed versions listed:</strong> ${escapeHtml(item.fixedVersions.join(", "))}</p>` : ""}
                  ${item.dependencyChain.length ? `<p><strong>Dependency chain:</strong> ${escapeHtml(item.dependencyChain.join(" → "))}</p>` : ""}
                  ${item.suggestedCommand ? `<p><strong>Suggested command:</strong></p><pre>${escapeHtml(item.suggestedCommand)}</pre>` : "<p><strong>Suggested command:</strong> No automatic command generated.</p>"}
                  ${item.advisoryUrl ? `<p><a href="${escapeHtml(item.advisoryUrl)}">View security advisory</a></p>` : ""}
                </article>
              `
            )
            .join("")
        : `<p>${securityReport?.status === "completed" ? "No known dependency vulnerabilities were detected in this scan." : `Security audit not completed: ${escapeHtml(securityReport?.message ?? "No security report available.")}`}</p>`;

    const checksHtml = report.checks.length
      ? report.checks
          .map(
            (check) => `
              <tr>
                <td>${escapeHtml(check.name)}</td>
                <td>${escapeHtml(check.status.toUpperCase())}</td>
                <td>${escapeHtml(check.message)}</td>
              </tr>
            `
          )
          .join("")
      : `<tr><td colspan="3">No diagnostic checks were returned.</td></tr>`;

    const issuesHtml = report.issues.length
      ? report.issues
          .map((issue) => {
            const fix = getFixSuggestion(issue);
            return `
              <article class="finding">
                <p><strong>${escapeHtml(issue.severity.toUpperCase())} · ${escapeHtml(issue.category)}</strong></p>
                <h3>${escapeHtml(issue.title)}</h3>
                <p>${escapeHtml(issue.message)}</p>
                ${issue.file ? `<p><strong>File:</strong> ${escapeHtml(issue.file)}</p>` : ""}
                <p><strong>Recommended solution:</strong> ${escapeHtml(fix.explanation)}</p>
                <ol>${fix.steps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ol>
                ${fix.code ? `<pre>${escapeHtml(fix.code)}</pre>` : ""}
                ${fix.caution ? `<p class="note"><strong>Caution:</strong> ${escapeHtml(fix.caution)}</p>` : ""}
              </article>
            `;
          })
          .join("")
      : "<p>No diagnostic issues were reported by the current checks.</p>";

    const comparisonHtml = securityComparison
      ? `
        <section>
          <h2>Security Fix Verification</h2>
          <p><strong>Previous scan:</strong> ${escapeHtml(new Date(securityComparison.previousScannedAt).toLocaleString())}</p>
          <p><strong>Current scan:</strong> ${escapeHtml(new Date(securityComparison.currentScannedAt).toLocaleString())}</p>
          <div class="metrics">
            <div class="metric"><strong>${securityComparison.noLongerDetected.length}</strong><span>No longer detected</span></div>
            <div class="metric"><strong>${securityComparison.stillDetected.length}</strong><span>Still detected</span></div>
            <div class="metric"><strong>${securityComparison.newlyDetected.length}</strong><span>Newly detected</span></div>
          </div>
          <p class="note">“No longer detected” means the matching advisory was not returned in the latest OSV scan. It is not proof of complete remediation or overall project security.</p>
        </section>
      `
      : "";

    const generatedAt = new Date().toLocaleString();
    const reportHtml = `
      <!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>${escapeHtml(report.projectName)} - Venom Project Doctor Report</title>
          <style>
            * { box-sizing: border-box; }
            html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
            body { margin: 32px; color: #202820; background: #fff; font: 11px/1.55 Arial, Helvetica, sans-serif; }
            .brand { color: #527d20; font-size: 10px; font-weight: 800; letter-spacing: 2px; }
            h1 { margin: 8px 0 2px; font-size: 27px; line-height: 1.2; }
            h2 { margin: 22px 0 11px; padding-bottom: 7px; border-bottom: 2px solid #b8f36b; font-size: 17px; line-height: 1.3; break-after: avoid-page; }
            h3 { margin: 5px 0; font-size: 13px; }
            p { margin: 5px 0; overflow-wrap: anywhere; }
            section { margin: 0 0 18px; }
            .muted { color: #68736b; }
            .score { margin: 8px 0; color: #527d20; font-size: 34px; font-weight: 800; }
            .metrics { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin: 12px 0; }
            .metric { padding: 9px 10px; border: 1px solid #dce4d8; border-radius: 7px; }
            .metric strong { display: block; font-size: 19px; }
            .metric span { color: #68736b; font-size: 9px; }
            table { width: 100%; margin-top: 10px; border-collapse: collapse; table-layout: fixed; }
            th, td { padding: 7px; border: 1px solid #dce4d8; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
            th { background: #eff5e9; }
            th:nth-child(1), td:nth-child(1) { width: 27%; }
            th:nth-child(2), td:nth-child(2) { width: 16%; white-space: nowrap; overflow-wrap: normal; }
            th:nth-child(3), td:nth-child(3) { width: 57%; }
            .finding { margin: 9px 0; padding: 11px; border: 1px solid #dce4d8; border-radius: 7px; break-inside: avoid; page-break-inside: avoid; }
            .finding-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
            .version { color: #68736b; font-size: 10px; font-weight: normal; }
            .severity { flex: 0 0 auto; white-space: nowrap; font-size: 9px; font-weight: 800; }
            .critical, .high { color: #b42318; }
            .moderate { color: #a16207; }
            .low { color: #1d4ed8; }
            pre { padding: 8px; border-radius: 5px; background: #f1f4ef; white-space: pre-wrap; overflow-wrap: anywhere; }
            a { color: #426d17; overflow-wrap: anywhere; }
            .note { padding: 9px; border-left: 3px solid #b8f36b; background: #f5f7f2; }
            .vulnerability-section { break-before: page; page-break-before: always; }
            .limitations { break-inside: avoid; page-break-inside: avoid; }
            footer { margin-top: 18px; padding-top: 9px; border-top: 1px solid #dce4d8; color: #68736b; font-size: 9px; break-inside: avoid; }
            @page {
              size: A4;
              margin: 16mm 14mm 19mm;
              @bottom-left { content: "VENOM PROJECT DOCTOR"; color: #68736b; font: 8px Arial, sans-serif; }
              @bottom-right { content: "Page " counter(page) " of " counter(pages); color: #68736b; font: 8px Arial, sans-serif; }
            }
            @media print {
              body { margin: 0; }
              a { color: #202820; }
              .finding, tr, .metric { break-inside: avoid; page-break-inside: avoid; }
              h2, h3 { break-after: avoid-page; }
            }
          </style>
        </head>
        <body>
          <header>
            <div class="brand">VENOM PROJECT DOCTOR</div>
            <h1>${escapeHtml(report.projectName)}</h1>
            <p class="muted">${escapeHtml(report.projectType)}</p>
            <p class="muted">Report generated: ${escapeHtml(generatedAt)} · Scan date: ${escapeHtml(new Date(report.scannedAt).toLocaleString())}</p>
          </header>

          <section>
            <h2>Project Health Summary</h2>
            <div class="score">${escapeHtml(report.healthScore)}%</div>
            <p>Preliminary structural diagnostic score. This is not a security score or proof of SDK compatibility.</p>
            <div class="metrics">
              <div class="metric"><strong>${report.summary.passed}</strong><span>Passed checks</span></div>
              <div class="metric"><strong>${report.summary.warnings}</strong><span>Warnings</span></div>
              <div class="metric"><strong>${report.summary.errors}</strong><span>Errors</span></div>
            </div>
          </section>

          <section>
            <h2>Security Audit</h2>
            <p><strong>Status:</strong> ${escapeHtml(securityReport?.status ?? "unavailable")}</p>
            <p>${escapeHtml(securityReport?.message ?? "No security report was returned.")}</p>
            <p><strong>Installed packages scanned:</strong> ${securityReport?.scannedPackages ?? "N/A"}</p>
            <div class="metrics">
              ${severityRows.map(([label, value]) => `<div class="metric"><strong>${value}</strong><span>${label}</span></div>`).join("")}
            </div>
          </section>

          <section class="vulnerability-section">
            <h2>Vulnerability Details</h2>
            ${vulnerabilityHtml}
          </section>
${contractGuardHtml}
          <section>
            <h2>Diagnostic Checks</h2>
            <table>
              <thead><tr><th>Check</th><th>Status</th><th>Details</th></tr></thead>
              <tbody>${checksHtml}</tbody>
            </table>
          </section>

          <section>
            <h2>Detected SDK Packages</h2>
            ${report.tools.length ? `<ul>${report.tools.map((tool) => `<li>${escapeHtml(tool.name)} — ${escapeHtml(tool.version)}</li>`).join("")}</ul>` : "<p>No recognized SDK packages found.</p>"}
          </section>

          <section>
            <h2>Diagnostic Issues and Fix Suggestions</h2>
            ${issuesHtml}
          </section>

          ${comparisonHtml}

          <section class="limitations">
            <h2>Report Limitations</h2>
            <p>This report summarizes the checks performed by Venom Project Doctor. The dependency audit checks known vulnerabilities using OSV data; it is not a complete source-code security audit.</p>
            <p>Upgrade risk and remediation guidance are preliminary, not compatibility guarantees. Review official release notes and run your project's tests before applying dependency changes.</p>
          </section>

          <footer>Generated locally in your browser · ${escapeHtml(generatedAt)}</footer>
          <script>
            window.addEventListener("load", () => {
              setTimeout(() => window.print(), 250);
            });
          </script>
        </body>
      </html>
    `;

    printWindow.document.open();
    printWindow.document.write(reportHtml);
    printWindow.document.close();
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
<section className="mb-5 rounded-2xl border border-[#b8f36b]/20 bg-[#101411] p-6 sm:p-8">
  <div className="mb-4 flex items-center gap-3">
    <div className="rounded-xl bg-[#b8f36b]/10 p-3 text-[#b8f36b]">
      <Activity size={22} />
    </div>
    <div>
      <h2 className="font-semibold">GitHub Repository Scanner</h2>
      <p className="mt-1 text-xs text-[#87938a]">
        Scan public GitHub repositories without downloading them.
      </p>
    </div>
  </div>

  <label
    htmlFor="github-repository"
    className="mb-2 block text-xs font-medium text-[#aeb9b0]"
  >
    Public GitHub repository URL
  </label>

  <input
    id="github-repository"
    type="url"
    value={githubRepositoryUrl}
    onChange={(event) => setGithubRepositoryUrl(event.target.value)}
    placeholder="https://github.com/owner/repository"
    disabled={loading}
    className="w-full rounded-lg border border-white/10 bg-[#090b0a] px-4 py-3 text-sm text-white outline-none transition placeholder:text-[#58645b] focus:border-[#b8f36b]/60 disabled:opacity-50"
  />

  <button
    type="button"
    onClick={scanGitHubRepository}
    disabled={loading || !githubRepositoryUrl.trim()}
    className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg bg-[#b8f36b] px-5 py-3.5 text-sm font-bold text-[#10150c] transition hover:bg-[#c8ff80] disabled:cursor-not-allowed disabled:opacity-40"
  >
    {loading ? (
      <>
        <Loader2 size={17} className="animate-spin" />
        Scanning GitHub repository...
      </>
    ) : (
      <>
        <ShieldCheck size={17} />
        Scan GitHub Repository
      </>
    )}
  </button>

  <p className="mt-3 text-center text-[11px] leading-5 text-[#667169]">
    Public repositories only · Read-only · Maximum 800 files and 5 MB
  </p>
</section>
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
            <span className="text-sm font-semibold">
              Choose project folder
            </span>
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

        {/* PERSISTENT SCAN HISTORY */}
        <section className="mt-5 rounded-xl border border-white/[0.08] bg-[#101411] p-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="font-semibold">Scan History</h3>
              <p className="mt-1 text-xs text-[#87938a]">
                Your latest 30 scan reports are saved in this browser.
              </p>
            </div>
            <span className="rounded-full bg-[#b8f36b]/10 px-3 py-1 text-xs text-[#b8f36b]">
              {scanHistory.length} saved
            </span>
          </div>

          {!historyReady ? (
            <p className="mt-4 text-sm text-[#87938a]">
              Loading saved scans...
            </p>
          ) : scanHistory.length === 0 ? (
            <p className="mt-4 rounded-lg border border-white/[0.07] bg-black/20 p-4 text-sm text-[#87938a]">
              No saved scans yet. Successful scans will appear here
              automatically.
            </p>
          ) : (
            <>
              <div className="mt-4 space-y-2">
                {scanHistory.map((item) => (
                  <div
                    key={item.id}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-white/[0.07] bg-black/20 p-3"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium text-[#e8eee9]">
                        {item.projectName}
                      </p>
                      <p className="mt-1 text-[11px] text-[#87938a]">
                        {new Date(item.savedAt).toLocaleString()} · Health{" "}
                        {item.report.healthScore}% ·{" "}
                        {item.securityReport?.status === "completed"
                          ? `${item.securityReport.summary.total} vulnerabilities`
                          : "Security audit unavailable"}
                      </p>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => downloadHistoryItem(item)}
                        className="rounded-md border border-white/10 px-2.5 py-1.5 text-[11px] hover:bg-white/5"
                      >
                        Export
                      </button>
                      <button
                        onClick={() => deleteHistoryItem(item.id)}
                        className="rounded-md border border-red-500/20 px-2.5 py-1.5 text-[11px] text-red-300 hover:bg-red-500/10"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                ))}
              </div>

              <div className="mt-5 border-t border-white/[0.08] pt-5">
                <h4 className="text-sm font-semibold">
                  Compare saved scans
                </h4>
                <p className="mt-1 text-xs text-[#87938a]">
                  Choose two scans of the same project.
                </p>

                <div className="mt-3 grid gap-3 sm:grid-cols-2">
                  <label className="text-xs text-[#87938a]">
                    Older scan
                    <select
                      value={compareFirstId}
                      onChange={(event) =>
                        setCompareFirstId(event.target.value)
                      }
                      className="mt-2 w-full rounded-lg border border-white/10 bg-[#090b0a] px-3 py-2.5 text-sm text-[#e8eee9]"
                    >
                      <option value="">Select older scan</option>
                      {scanHistory.map((item) => (
                        <option key={item.id} value={item.id}>
                          {item.projectName} ·{" "}
                          {new Date(item.savedAt).toLocaleString()}
                        </option>
                      ))}
                    </select>
                  </label>

                  <label className="text-xs text-[#87938a]">
                    Newer scan
                    <select
                      value={compareSecondId}
                      onChange={(event) =>
                        setCompareSecondId(event.target.value)
                      }
                      className="mt-2 w-full rounded-lg border border-white/10 bg-[#090b0a] px-3 py-2.5 text-sm text-[#e8eee9]"
                    >
                      <option value="">Select newer scan</option>
                      {scanHistory.map((item) => (
                        <option key={item.id} value={item.id}>
                          {item.projectName} ·{" "}
                          {new Date(item.savedAt).toLocaleString()}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>

                {compareFirstId &&
                  compareSecondId &&
                  (() => {
                    const older = scanHistory.find(
                      (item) => item.id === compareFirstId
                    );
                    const newer = scanHistory.find(
                      (item) => item.id === compareSecondId
                    );

                    if (!older || !newer) return null;

                    if (older.id === newer.id) {
                      return (
                        <p className="mt-3 text-xs text-amber-300">
                          Choose two different scans.
                        </p>
                      );
                    }

                    if (older.projectName !== newer.projectName) {
                      return (
                        <p className="mt-3 text-xs text-amber-300">
                          Choose scans belonging to the same project.
                        </p>
                      );
                    }

                    if (older.savedAt > newer.savedAt) {
                      return (
                        <p className="mt-3 text-xs text-amber-300">
                          The older scan must be earlier than the newer scan.
                        </p>
                      );
                    }

                    if (
                      older.securityReport?.status !== "completed" ||
                      newer.securityReport?.status !== "completed"
                    ) {
                      return (
                        <p className="mt-3 text-xs text-amber-300">
                          Both scans must have completed security audits.
                        </p>
                      );
                    }

                    const comparison = compareSecurityReports(
                      older.securityReport,
                      newer.securityReport,
                      older.report.scannedAt,
                      newer.report.scannedAt
                    );

                    return (
                      <div className="mt-4 rounded-lg border border-[#b8f36b]/15 bg-[#0b100c] p-4">
                        <div className="grid grid-cols-3 gap-2 text-center">
                          <div>
                            <p className="text-xl font-bold text-[#b8f36b]">
                              {comparison.noLongerDetected.length}
                            </p>
                            <p className="mt-1 text-[10px] text-[#87938a]">
                              No longer detected
                            </p>
                          </div>
                          <div>
                            <p className="text-xl font-bold text-amber-300">
                              {comparison.stillDetected.length}
                            </p>
                            <p className="mt-1 text-[10px] text-[#87938a]">
                              Still detected
                            </p>
                          </div>
                          <div>
                            <p className="text-xl font-bold text-red-400">
                              {comparison.newlyDetected.length}
                            </p>
                            <p className="mt-1 text-[10px] text-[#87938a]">
                              Newly detected
                            </p>
                          </div>
                        </div>

                        {[
                          {
                            title: "No longer detected",
                            items: comparison.noLongerDetected,
                          },
                          {
                            title: "Still detected",
                            items: comparison.stillDetected,
                          },
                          {
                            title: "Newly detected",
                            items: comparison.newlyDetected,
                          },
                        ].map((group) => (
                          <div
                            key={group.title}
                            className="mt-4 border-t border-white/[0.07] pt-3"
                          >
                            <p className="text-xs font-semibold text-[#e8eee9]">
                              {group.title}
                            </p>

                            {group.items.length === 0 ? (
                              <p className="mt-1 text-[11px] text-[#87938a]">
                                None
                              </p>
                            ) : (
                              group.items.map((item, index) => (
                                <p
                                  key={`${item.id}-${item.name}-${index}`}
                                  className="mt-1 flex flex-wrap justify-between gap-2 text-[11px] text-[#aab5ad]"
                                >
                                  <span>{item.name}</span>
                                  <span>
                                    {item.id} · v{item.version}
                                  </span>
                                </p>
                              ))
                            )}
                          </div>
                        ))}

                        <p className="mt-4 text-[10px] leading-5 text-[#667169]">
                          “No longer detected” means OSV did not return the
                          advisory in the latest scan; it is not proof of
                          complete security.
                        </p>
                      </div>
                    );
                  })()}
              </div>
            </>
          )}

          <p className="mt-4 border-t border-white/[0.07] pt-3 text-[10px] leading-5 text-[#667169]">
            History is stored in this browser only, not uploaded to a server.
            It may not appear on another device or browser. The latest 30 scans
            are retained.
          </p>
        </section>

        {/* SECURITY AUDIT */}
        <div className="rounded-xl border border-white/10 bg-[#101711] p-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <ShieldCheck className="text-[#b8f36b]" size={22} />
              <div>
                <h3 className="text-lg font-semibold">Security Audit</h3>
                <p className="mt-1 text-xs text-[#87938a]">
                  Known vulnerabilities in installed dependencies
                </p>
              </div>
            </div>


            {securityReport && (
              <span
                className={`rounded-full px-3 py-1 text-xs ${
                  securityReport.status === "completed"
                    ? "bg-[#b8f36b]/10 text-[#b8f36b]"
                    : "bg-amber-500/10 text-amber-300"
                }`}
              >
                {securityReport.status.toUpperCase()}
              </span>
            )}
          </div>

          {!securityReport ? (
            <p className="mt-5 text-sm text-amber-300">
              Security audit result was not returned by the server.
            </p>
          ) : (
            <>
              <p className="mt-4 text-sm text-[#aab5ad]">
                {securityReport.message}
              </p>

              {securityReport.status === "completed" && (
                <>
                  <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
                    {[
                      {
                        label: "Total",
                        value: securityReport.summary.total,
                        color: "text-white",
                      },
                      {
                        label: "Critical",
                        value: securityReport.summary.critical,
                        color: "text-red-400",
                      },
                      {
                        label: "High",
                        value: securityReport.summary.high,
                        color: "text-orange-400",
                      },
                      {
                        label: "Moderate",
                        value: securityReport.summary.moderate,
                        color: "text-amber-300",
                      },
                      {
                        label: "Low",
                        value: securityReport.summary.low,
                        color: "text-blue-300",
                      },
                      {
                        label: "Info",
                        value: securityReport.summary.info,
                        color: "text-[#87938a]",
                      },
                    ].map((item) => (
                      <div
                        key={item.label}
                        className="rounded-lg border border-white/10 bg-black/20 p-3"
                      >
                        <div className={`text-2xl font-bold ${item.color}`}>
                          {item.value}
                        </div>
                        <div className="mt-1 text-xs text-[#87938a]">
                          {item.label}
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className="mt-4 text-xs text-[#87938a]">
                    Scanned {securityReport.scannedPackages} installed package
                    {securityReport.scannedPackages === 1 ? "" : "s"}.
                  </div>

                  {securityReport.vulnerabilities.length === 0 ? (
                    <div className="mt-5 rounded-lg border border-[#b8f36b]/20 bg-[#b8f36b]/5 p-4">
                      <div className="flex items-center gap-2 text-sm font-semibold text-[#b8f36b]">
                        <CheckCircle2 size={17} />
                        No known vulnerabilities found
                      </div>
                      <p className="mt-2 text-xs text-[#aab5ad]">
                        No matching advisories were found for the scanned
                        dependency versions. This does not guarantee that the
                        project is completely secure.
                      </p>
                    </div>
                  ) : (
                    <div className="mt-6 space-y-4">
                      {securityReport.vulnerabilities.map(
                        (vulnerability, index) => {
                          const severityStyles: Record<string, string> = {
                            critical:
                              "bg-red-500/10 text-red-400 border-red-500/20",
                            high:
                              "bg-orange-500/10 text-orange-400 border-orange-500/20",
                            moderate:
                              "bg-amber-500/10 text-amber-300 border-amber-500/20",
                            low:
                              "bg-blue-500/10 text-blue-300 border-blue-500/20",
                            info: "bg-white/5 text-[#aab5ad] border-white/10",
                            unknown:
                              "bg-white/5 text-[#aab5ad] border-white/10",
                          };

                          return (
                            <div
                              key={`${vulnerability.id}-${vulnerability.name}-${vulnerability.version}-${index}`}
                              className="rounded-lg border border-white/10 bg-black/20 p-4"
                            >
                              <div className="flex flex-wrap items-center gap-2">
                                <span
                                  className={`rounded border px-2 py-1 text-[10px] font-semibold uppercase ${
                                    severityStyles[vulnerability.severity] ??
                                    severityStyles.unknown
                                  }`}
                                >
                                  {vulnerability.severity}
                                </span>

                                <span className="text-sm font-semibold">
                                  {vulnerability.name}
                                </span>

                                <span className="text-xs text-[#87938a]">
                                  v{vulnerability.version}
                                </span>

                                <span className="rounded bg-white/5 px-2 py-1 text-[10px] text-[#aab5ad]">
                                  {vulnerability.isDirect
                                    ? "Direct"
                                    : "Transitive"}
                                </span>
                              </div>

                              <p className="mt-3 text-sm text-[#e8eee9]">
                                {vulnerability.summary}
                              </p>

                              <div className="mt-3 space-y-2 text-xs text-[#aab5ad]">
                                <p>
                                  <span className="text-[#87938a]">
                                    Advisory:
                                  </span>{" "}
                                  {vulnerability.id}
                                </p>

                                {vulnerability.affectedRange && (
                                  <p>
                                    <span className="text-[#87938a]">
                                      Affected range:
                                    </span>{" "}
                                    {vulnerability.affectedRange}
                                  </p>
                                )}

                                {vulnerability.fixedVersions.length > 0 && (
                                  <p>
                                    <span className="text-[#87938a]">
                                      Listed fixed versions:
                                    </span>{" "}
                                    {vulnerability.fixedVersions.join(", ")}
                                  </p>
                                )}

                                {vulnerability.locations.length > 0 && (
                                  <div>
                                    <span className="text-[#87938a]">
                                      Installed locations:
                                    </span>
                                    <ul className="mt-1 space-y-1">
                                      {vulnerability.locations.map(
                                        (location) => (
                                          <li
                                            key={location}
                                            className="break-all font-mono"
                                          >
                                            {location}
                                          </li>
                                        )
                                      )}
                                    </ul>
                                  </div>
                                )}
                              </div>

                              <div className="mt-4 rounded-lg border border-[#b8f36b]/10 bg-[#b8f36b]/5 p-3">
                                <p className="text-xs font-semibold text-[#b8f36b]">
                                  Remediation guidance
                                </p>
                                <p className="mt-2 text-xs leading-5 text-[#c2ccc4]">
                                  {vulnerability.remediation}
                                </p>
                              </div>

                              {vulnerability.advisoryUrl && (
                                <a
                                  href={vulnerability.advisoryUrl}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="mt-3 inline-flex text-xs text-[#b8f36b] hover:underline"
                                >
                                  View security advisory ↗
                                </a>
                              )}
                            </div>
                          );
                        }
                      )}
                    </div>
                  )}
                </>
              )}
            </>
          )}

          <p className="mt-5 border-t border-white/10 pt-4 text-[11px] leading-5 text-[#87938a]">
            This audit checks known vulnerabilities in installed dependencies
            using OSV data. It is not a complete source-code security audit.
            Review advisories and test dependency upgrades before applying them.
          </p>
        </div>
{report && (
  <div className="mt-5">
    <ContractGuardPanel report={contractSecurityReport} />
  </div>
)}
        {/* SECURITY FIX VERIFICATION */}
        <div className="mt-5 rounded-xl border border-[#b8f36b]/20 bg-[#101711] p-6">
          <div className="flex items-center gap-3">
            <CheckCircle2 size={21} className="text-[#b8f36b]" />
            <div>
              <h3 className="font-semibold">Security Fix Verification</h3>
              <p className="mt-1 text-xs text-[#87938a]">
                Compare successful scans to see which known dependency
                advisories changed.
              </p>
            </div>
          </div>

          {!securityComparison ? (
            <div className="mt-4 rounded-lg border border-white/[0.07] bg-black/20 p-4">
              <p className="text-sm text-[#aab5ad]">
                {previousSecurityReport?.status === "completed"
                  ? "A new baseline has been saved. Run another successful scan of this same project after making dependency changes to verify them."
                  : "Your first successful security scan becomes the baseline. After updating dependencies, run another successful scan to compare the results."}
              </p>
            </div>
          ) : (
            <>
              <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div className="rounded-lg border border-[#b8f36b]/20 bg-[#b8f36b]/[0.05] p-4">
                  <div className="text-2xl font-bold text-[#b8f36b]">
                    {securityComparison.noLongerDetected.length}
                  </div>
                  <div className="mt-1 text-xs text-[#aab5ad]">
                    No longer detected
                  </div>
                </div>

                <div className="rounded-lg border border-amber-500/20 bg-amber-500/[0.04] p-4">
                  <div className="text-2xl font-bold text-amber-300">
                    {securityComparison.stillDetected.length}
                  </div>
                  <div className="mt-1 text-xs text-[#aab5ad]">
                    Still detected
                  </div>
                </div>

                <div className="rounded-lg border border-red-500/20 bg-red-500/[0.04] p-4">
                  <div className="text-2xl font-bold text-red-400">
                    {securityComparison.newlyDetected.length}
                  </div>
                  <div className="mt-1 text-xs text-[#aab5ad]">
                    Newly detected
                  </div>
                </div>
              </div>

              <div className="mt-4 space-y-4">
                {[
                  {
                    title: "No longer detected",
                    description:
                      "These advisory/package matches appeared in the previous scan but not in the latest scan.",
                    items: securityComparison.noLongerDetected,
                    color: "text-[#b8f36b]",
                  },
                  {
                    title: "Still detected",
                    description:
                      "These advisory/package matches remain in the latest scan.",
                    items: securityComparison.stillDetected,
                    color: "text-amber-300",
                  },
                  {
                    title: "Newly detected",
                    description:
                      "These advisory/package matches were not present in the previous scan.",
                    items: securityComparison.newlyDetected,
                    color: "text-red-400",
                  },
                ].map((group) => (
                  <div
                    key={group.title}
                    className="rounded-lg border border-white/[0.07] bg-black/20 p-4"
                  >
                    <h4 className={`text-sm font-semibold ${group.color}`}>
                      {group.title} ({group.items.length})
                    </h4>

                    {group.items.length === 0 ? (
                      <p className="mt-2 text-xs text-[#87938a]">
                        None in this comparison.
                      </p>
                    ) : (
                      <ul className="mt-3 space-y-2">
                        {group.items.map((item, index) => (
                          <li
                            key={`${item.id}-${item.name}-${index}`}
                            className="flex flex-wrap items-center justify-between gap-2 text-xs"
                          >
                            <span className="font-medium text-[#e8eee9]">
                              {item.name}
                            </span>
                            <span className="text-[#87938a]">
                              {item.id} · v{item.version}
                            </span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                ))}
              </div>

              <p className="mt-4 border-t border-white/10 pt-4 text-[11px] leading-5 text-[#87938a]">
                Compared scans from{" "}
                {new Date(
                  securityComparison.previousScannedAt
                ).toLocaleString()}{" "}
                and{" "}
                {new Date(
                  securityComparison.currentScannedAt
                ).toLocaleString()}
                . “No longer detected” means OSV did not return the matching
                advisory in the latest scan; it is not proof that the project
                is completely secure.
              </p>
            </>
          )}
        </div>

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

                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={downloadPdfReport}
                    className="flex items-center justify-center gap-2 rounded-lg bg-[#b8f36b] px-4 py-2.5 text-xs font-bold text-[#10150c] hover:bg-[#c8ff80]"
                  >
                    <Download size={15} /> Export PDF
                  </button>
                  <button
                    onClick={downloadReport}
                    className="flex items-center justify-center gap-2 rounded-lg border border-white/10 px-4 py-2.5 text-xs hover:bg-white/5"
                  >
                    <Download size={15} /> Download JSON
                  </button>
                </div>
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

            {/* SECURITY REMEDIATION DETAILS */}
            <div className="rounded-xl border border-[#b8f36b]/20 bg-[#101711] p-6">
              <div className="flex items-center gap-3">
                <ShieldCheck size={21} className="text-[#b8f36b]" />
                <div>
                  <h3 className="font-semibold">Security Remediation</h3>
                  <p className="mt-1 text-xs text-[#87938a]">
                    Dependency upgrade guidance based on detected
                    vulnerabilities.
                  </p>
                </div>
              </div>

              {!securityReport ? (
                <p className="mt-5 text-sm text-amber-300">
                  Security report is not available.
                </p>
              ) : securityReport.status !== "completed" ? (
                <p className="mt-5 text-sm text-amber-300">
                  {securityReport.message}
                </p>
              ) : securityReport.vulnerabilities.length === 0 ? (
                <p className="mt-5 text-sm text-[#b8f36b]">
                  No known dependency vulnerabilities were detected.
                </p>
              ) : (
                <div className="mt-5 space-y-4">
                  {securityReport.vulnerabilities.map((item, index) => {
                    const riskStyles = {
                      patch: "text-[#b8f36b] bg-[#b8f36b]/10",
                      minor: "text-amber-300 bg-amber-500/10",
                      major: "text-orange-400 bg-orange-500/10",
                      unknown: "text-[#87938a] bg-white/5",
                    };

                    return (
                      <div
                        key={`${item.id}-${item.name}-${item.version}-${index}`}
                        className="rounded-xl border border-white/[0.08] bg-[#0c100d] p-4"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div>
                            <h4 className="text-sm font-semibold">
                              {item.name}
                            </h4>
                            <p className="mt-1 text-xs text-[#87938a]">
                              Installed version: {item.version}
                            </p>
                          </div>

                          <span
                            className={`rounded-md px-2 py-1 text-[10px] font-bold uppercase ${riskStyles[item.upgradeRisk]}`}
                          >
                            {item.upgradeRisk} upgrade
                          </span>
                        </div>

                        <div className="mt-4 flex flex-wrap gap-2">
                          <span className="rounded-md bg-white/5 px-2 py-1 text-[10px] text-[#aab5ad]">
                            {item.isDirect
                              ? "Direct dependency"
                              : "Transitive dependency"}
                          </span>

                          <span className="rounded-md bg-white/5 px-2 py-1 text-[10px] text-[#aab5ad]">
                            {item.severity.toUpperCase()}
                          </span>
                        </div>

                        <div className="mt-4">
                          <p className="text-xs text-[#87938a]">
                            Dependency context
                          </p>

                          <p className="mt-2 break-all text-xs text-[#b8f36b]">
                            {item.dependencyChain.length > 1
                              ? item.dependencyChain.join(" → ")
                              : item.isDirect
                                ? "Root project → " + item.name
                                : "Parent dependency not confirmed"}
                          </p>

                          {item.nearestNestedPackage && (
                            <p className="mt-2 text-[11px] text-[#87938a]">
                              Nearest nested package:{" "}
                              {item.nearestNestedPackage}
                            </p>
                          )}
                        </div>

                        {item.fixedVersions.length > 0 && (
                          <div className="mt-4">
                            <p className="text-xs text-[#87938a]">
                              Versions listed as fixed
                            </p>
                            <p className="mt-1 text-xs text-[#b8f36b]">
                              {item.fixedVersions.join(", ")}
                            </p>
                          </div>
                        )}

                        <div className="mt-4 rounded-lg border border-white/[0.07] bg-black/20 p-3">
                          <p className="text-xs font-semibold text-[#b8f36b]">
                            Recommended action
                          </p>

                          <p className="mt-2 text-xs leading-5 text-[#aab5ad]">
                            {item.remediation}
                          </p>

                          {item.suggestedCommand ? (
                            <div className="mt-3">
                              <pre className="overflow-x-auto rounded-lg bg-black/40 p-3 text-xs text-[#b8f36b]">
                                {item.suggestedCommand}
                              </pre>

                              <button
                                onClick={() =>
                                  copyFix(
                                    item.suggestedCommand!,
                                    `security-fix-${index}`
                                  )
                                }
                                className="mt-2 flex items-center gap-2 rounded-md border border-white/10 px-3 py-2 text-xs hover:bg-white/5"
                              >
                                {copied === `security-fix-${index}` ? (
                                  <>
                                    <Check
                                      size={13}
                                      className="text-[#b8f36b]"
                                    />
                                    Copied
                                  </>
                                ) : (
                                  <>
                                    <Copy size={13} />
                                    Copy npm command
                                  </>
                                )}
                              </button>
                            </div>
                          ) : (
                            <p className="mt-3 text-[11px] leading-5 text-amber-300">
                              No automatic upgrade command generated. Review
                              the parent dependency and its supported versions
                              before choosing an upgrade.
                            </p>
                          )}
                        </div>

                        {item.locations.length > 0 && (
                          <div className="mt-3">
                            <p className="text-[11px] text-[#87938a]">
                              Installed locations
                            </p>
                            {item.locations.map((location) => (
                              <p
                                key={location}
                                className="mt-1 break-all font-mono text-[10px] text-[#667169]"
                              >
                                {location}
                              </p>
                            ))}
                          </div>
                        )}

                        {item.advisoryUrl && (
                          <a
                            href={item.advisoryUrl}
                            target="_blank"
                            rel="noreferrer"
                            className="mt-3 inline-block text-xs text-[#b8f36b] hover:underline"
                          >
                            Read security advisory ↗
                          </a>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}

              <p className="mt-5 border-t border-white/10 pt-4 text-[11px] leading-5 text-[#667169]">
                Upgrade risk is a preliminary version comparison, not a
                compatibility guarantee. Always review release notes and test
                your project after dependency changes.
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
                                      <Check
                                        size={13}
                                        className="text-[#b8f36b]"
                                      />
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
