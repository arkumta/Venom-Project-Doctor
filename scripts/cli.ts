
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { scanProject, type ProjectFile } from "../lib/scanner";

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

function printReport(report: ReturnType<typeof scanProject>) {
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

      if (issue.file) console.log(`    File: ${issue.file}`);
    }
  }

  console.log("\n======================================");
  console.log("Scan completed.");
  console.log("======================================\n");
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  const jsonOutput = args.includes("--json");

  if (!command || command === "--help" || command === "-h") {
    console.log(`
Venom Project Doctor CLI

Usage:
  npm run doctor -- scan
  npm run doctor -- scan <project-folder>
  npm run doctor -- scan <project-folder> --json

Commands:
  scan       Scan a project directory
  --help     Show help
`);
    return;
  }

  if (command !== "scan") {
    throw new Error(`Unknown command: ${command}. Use --help.`);
  }

  const targetArgument = args.find(
    (arg, index) => index > 0 && !arg.startsWith("--")
  );

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

  const report = scanProject(files);

  if (jsonOutput) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    printReport(report);
  }

  if (report.summary.errors > 0) {
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
