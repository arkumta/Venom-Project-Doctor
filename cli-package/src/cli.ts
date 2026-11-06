
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { scanProject, type ProjectFile } from "./scanner";
import { scanSecurity, type SecurityAuditReport } from "./security";

const ignoredDirectories = new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  "coverage",
  ".turbo",
  ".vercel",
]);

const allowedExtensions = new Set([
  ".json",
  ".ts",
  ".js",
  ".cjs",
  ".mjs",
  ".sol",
  ".leo",
]);

const sensitiveFiles = new Set([
  ".npmrc",
  ".pypirc",
  "id_rsa",
  "id_ed25519",
]);

const MAX_FILES = 500;
const MAX_SIZE = 5 * 1024 * 1024;

const severityLevels = {
  critical: 5,
  high: 4,
  moderate: 3,
  low: 2,
  info: 1,
} as const;

type FailOnSeverity = keyof typeof severityLevels;

function isFailOnSeverity(value: string): value is FailOnSeverity {
  return Object.prototype.hasOwnProperty.call(severityLevels, value);
}

function shouldIncludeFile(filename: string): boolean {
  if (filename.startsWith(".env")) return false;
  if (sensitiveFiles.has(filename)) return false;

  return (
    filename === "package.json" ||
    /^locklift\.config\.(ts|js|cjs|mjs)$/.test(filename) ||
    allowedExtensions.has(path.extname(filename).toLowerCase())
  );
}

async function collectFiles(
  directory: string,
  root: string,
  results: ProjectFile[]
): Promise<void> {
  const entries = await readdir(directory, { withFileTypes: true });

  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;

    const fullPath = path.join(directory, entry.name);

    if (entry.isDirectory()) {
      if (ignoredDirectories.has(entry.name)) continue;
      await collectFiles(fullPath, root, results);
      continue;
    }

    if (!entry.isFile() || !shouldIncludeFile(entry.name)) continue;

    if (results.length >= MAX_FILES) {
      throw new Error(`Project exceeds the ${MAX_FILES} file limit.`);
    }

    const content = await readFile(fullPath, "utf8");

    results.push({
      path: path.relative(root, fullPath).split(path.sep).join("/"),
      content,
    });

    const totalSize = results.reduce(
      (sum, file) => sum + Buffer.byteLength(file.content, "utf8"),
      0
    );

    if (totalSize > MAX_SIZE) {
      throw new Error("Project files exceed the 5 MB scanning limit.");
    }
  }
}

function printSecurityReport(report: SecurityAuditReport) {
  console.log("\nSECURITY AUDIT");
  console.log("--------------------------------------");

  console.log(`Status: ${report.status}`);
  console.log(report.message);

  if (report.status !== "completed") return;

  console.log("\nVULNERABILITY SUMMARY");
  console.log("--------------------------------------");
  console.log(`Total:    ${report.summary.total}`);
  console.log(`Critical: ${report.summary.critical}`);
  console.log(`High:     ${report.summary.high}`);
  console.log(`Moderate: ${report.summary.moderate}`);
  console.log(`Low:      ${report.summary.low}`);
  console.log(`Info:     ${report.summary.info}`);

  if (!report.vulnerabilities.length) {
    console.log("\nNo vulnerable packages reported.");
    return;
  }

  console.log("\nAFFECTED PACKAGES");
  console.log("--------------------------------------");

  for (const vulnerability of report.vulnerabilities) {
    console.log(
      `\n[${vulnerability.severity.toUpperCase()}] ${vulnerability.name}`
    );

    console.log(
      `    Dependency type: ${vulnerability.isDirect ? "Direct" : "Transitive"}`
    );

    console.log(`    Affected range: ${vulnerability.range}`);

    if (vulnerability.introducedBy.length) {
      console.log(
        `    Introduced by: ${vulnerability.introducedBy.join(", ")}`
      );
    }

    if (vulnerability.affectedPackages.length) {
      console.log(
        `    Affects: ${vulnerability.affectedPackages.join(", ")}`
      );
    }

    if (vulnerability.installedLocations.length) {
      console.log("    Installed locations:");

      for (const location of vulnerability.installedLocations) {
        console.log(`      - ${location}`);
      }
    }

    console.log(
      `    Fix available: ${vulnerability.fixAvailable ? "Yes" : "No"}`
    );

    if (vulnerability.fixVersion) {
      console.log(`    Recommended version: ${vulnerability.fixVersion}`);
    }

    if (vulnerability.requiresMajorUpgrade) {
      console.log("    Warning: Fix requires a major version upgrade.");
    }

    console.log(`    Remediation: ${vulnerability.remediation}`);
    console.log(`    Details: ${vulnerability.description}`);

    if (vulnerability.advisoryUrl) {
      console.log(`    Advisory: ${vulnerability.advisoryUrl}`);
    }
  }
}

function printReport(
  report: ReturnType<typeof scanProject>,
  security: SecurityAuditReport
) {
  console.log("\n======================================");
  console.log("       VENOM PROJECT DOCTOR");
  console.log("======================================\n");

  console.log(`Project: ${report.projectName}`);
  console.log(`Type: ${report.projectType}`);
  console.log(`Health score: ${report.healthScore}%`);

  console.log("\nSUMMARY");
  console.log("--------------------------------------");
  console.log(`Checks:   ${report.summary.totalChecks}`);
  console.log(`Passed:   ${report.summary.passed}`);
  console.log(`Warnings: ${report.summary.warnings}`);
  console.log(`Errors:   ${report.summary.errors}`);

  console.log("\nDIAGNOSTIC CHECKS");
  console.log("--------------------------------------");

  for (const check of report.checks) {
    const symbol =
      check.status === "passed"
        ? "✓"
        : check.status === "failed"
          ? "✗"
          : "!";

    console.log(`\n[${symbol}] ${check.name}`);
    console.log(`    ${check.message}`);
  }

  console.log("\nDETECTED SDK PACKAGES");
  console.log("--------------------------------------");

  if (!report.tools.length) {
    console.log("No recognized SDK packages found.");
  } else {
    for (const tool of report.tools) {
      console.log(`${tool.name}: ${tool.version}`);
    }
  }

  console.log("\nISSUES AND SUGGESTIONS");
  console.log("--------------------------------------");

  if (!report.issues.length) {
    console.log("No issues reported.");
  } else {
    for (const issue of report.issues) {
      console.log(`\n[${issue.severity.toUpperCase()}] ${issue.title}`);
      console.log(`    ${issue.message}`);

      if (issue.file) {
        console.log(`    File: ${issue.file}`);
      }
    }
  }

  printSecurityReport(security);

  console.log("\n======================================");
  console.log("Scan completed.");
  console.log("======================================\n");
}

function findFailingVulnerabilities(
  report: SecurityAuditReport,
  threshold: FailOnSeverity
) {
  if (report.status !== "completed") return [];

  const thresholdLevel = severityLevels[threshold];

  return report.vulnerabilities.filter((vulnerability) => {
    const severity = vulnerability.severity.toLowerCase();

    if (!isFailOnSeverity(severity)) return false;

    return severityLevels[severity] >= thresholdLevel;
  });
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  const jsonOutput = args.includes("--json");

  let failOn: FailOnSeverity | undefined;
  let targetArgument: string | undefined;

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];

    if (arg === "--json") continue;

    if (arg === "--help" || arg === "-h") {
      continue;
    }

    if (arg === "--fail-on") {
      const value = args[i + 1];

      if (!value || value.startsWith("--")) {
        throw new Error(
          "Missing severity after --fail-on. Use critical, high, moderate, low, or info."
        );
      }

      const normalizedValue = value.toLowerCase();

      if (!isFailOnSeverity(normalizedValue)) {
        throw new Error(
          `Invalid severity "${value}". Choose critical, high, moderate, low, or info.`
        );
      }

      failOn = normalizedValue;
      i++;
      continue;
    }

    if (arg.startsWith("--fail-on=")) {
      const value = arg.slice("--fail-on=".length).toLowerCase();

      if (!isFailOnSeverity(value)) {
        throw new Error(
          `Invalid severity "${value}". Choose critical, high, moderate, low, or info.`
        );
      }

      failOn = value;
      continue;
    }

    if (arg.startsWith("--")) {
      throw new Error(`Unknown option: ${arg}. Use --help.`);
    }

    if (!targetArgument) {
      targetArgument = arg;
    } else {
      throw new Error(`Unexpected argument: ${arg}`);
    }
  }

  if (!command || command === "--help" || command === "-h") {
    console.log(`
Venom Project Doctor CLI

Usage:
  venom-doctor scan
  venom-doctor scan <project-folder>
  venom-doctor scan <project-folder> --json
  venom-doctor scan . --fail-on high

Options:
  --json                 Output the report as JSON
  --fail-on <severity>   Exit with code 1 at this severity or higher
                         critical, high, moderate, low, info
  --help                 Show this help message
`);
    return;
  }

  if (command !== "scan") {
    throw new Error(`Unknown command: ${command}. Use --help.`);
  }

  const root = path.resolve(process.cwd(), targetArgument || ".");
  const rootStats = await stat(root);

  if (!rootStats.isDirectory()) {
    throw new Error("The selected project path is not a directory.");
  }

  const files: ProjectFile[] = [];
  await collectFiles(root, root, files);

  if (!files.length) {
    throw new Error("No supported project files found.");
  }

  if (!jsonOutput) {
    console.log("Running project diagnostics...");
  }

  const report = scanProject(files);

  if (!jsonOutput) {
    console.log("Running npm security audit...");
  }

  const security = await scanSecurity(root);

  const failingVulnerabilities = failOn
    ? findFailingVulnerabilities(security, failOn)
    : [];

  if (jsonOutput) {
    console.log(
      JSON.stringify(
        {
          ...report,
          securityAudit: security,
          failOn: failOn || null,
          securityPolicyFailed: failingVulnerabilities.length > 0,
        },
        null,
        2
      )
    );
  } else {
    printReport(report, security);

    if (failOn) {
      console.log(`Security threshold: ${failOn.toUpperCase()}`);

      if (failingVulnerabilities.length > 0) {
        console.log(
          `Security policy failed: ${failingVulnerabilities.length} vulnerability(ies) met or exceeded the threshold.`
        );
      } else {
        console.log("Security policy passed.");
      }
    }
  }

  // Configuration errors still fail the scan.
  if (report.summary.errors > 0) {
    process.exitCode = 1;
  }

  // Security findings only fail the scan when --fail-on is provided.
  if (failingVulnerabilities.length > 0) {
    process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  console.error(
    "\nScan failed:",
    error instanceof Error ? error.message : error
  );
  process.exitCode = 1;
});
