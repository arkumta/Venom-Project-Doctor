"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanSecurity = scanSecurity;
const node_child_process_1 = require("node:child_process");
const promises_1 = require("node:fs/promises");
const node_path_1 = __importDefault(require("node:path"));
const emptySummary = {
    total: 0,
    critical: 0,
    high: 0,
    moderate: 0,
    low: 0,
    info: 0,
};
function runNpmAudit(root) {
    return new Promise((resolve, reject) => {
        (0, node_child_process_1.execFile)("npm", ["audit", "--json"], {
            cwd: root,
            encoding: "utf8",
            timeout: 120000,
            maxBuffer: 10 * 1024 * 1024,
        }, (error, stdout, stderr) => {
            // npm audit can exit with code 1 when vulnerabilities exist.
            // Its JSON output is still valid and should be processed.
            if (stdout && stdout.trim()) {
                resolve(stdout);
                return;
            }
            reject(new Error(stderr?.trim() ||
                error?.message ||
                "npm audit did not return a report."));
        });
    });
}
function getRemediation(fixAvailable, fixVersion, requiresMajorUpgrade) {
    if (!fixAvailable) {
        return "No automatic fix was identified. Review the advisory and consider upgrading or replacing the affected dependency.";
    }
    if (requiresMajorUpgrade && fixVersion) {
        return `A fix is available in version ${fixVersion}, but it requires a major upgrade. Review breaking changes and test before upgrading.`;
    }
    if (requiresMajorUpgrade) {
        return "A fix is available, but it requires a major upgrade. Review breaking changes and test before upgrading.";
    }
    if (fixVersion) {
        return `Review upgrading to version ${fixVersion}. Test the project after updating dependencies.`;
    }
    return "npm reports that a fix is available, but did not provide an exact version. Review the dependency update suggested by npm before applying it.";
}
async function scanSecurity(projectRoot) {
    const lockfilePath = node_path_1.default.join(projectRoot, "package-lock.json");
    try {
        await (0, promises_1.access)(lockfilePath);
    }
    catch {
        return {
            status: "skipped",
            message: "Security audit skipped because package-lock.json was not found. Generate an npm lockfile before running npm audit.",
            summary: { ...emptySummary },
            vulnerabilities: [],
        };
    }
    let output;
    try {
        output = await runNpmAudit(projectRoot);
    }
    catch (error) {
        return {
            status: "unavailable",
            message: error instanceof Error
                ? error.message
                : "Unable to run npm audit.",
            summary: { ...emptySummary },
            vulnerabilities: [],
        };
    }
    try {
        const data = JSON.parse(output);
        const counts = data.metadata?.vulnerabilities ?? {};
        const rawVulnerabilities = data.vulnerabilities ?? {};
        const vulnerabilities = Object.entries(rawVulnerabilities).map(([packageName, vulnerability]) => {
            const via = vulnerability.via ?? [];
            const advisories = via.filter((item) => typeof item === "object" && item !== null);
            const introducedBy = via.filter((item) => typeof item === "string");
            const descriptions = advisories
                .map((item) => item.title || item.name || "")
                .filter(Boolean);
            const advisoryUrl = advisories.find((item) => item.url)?.url ?? null;
            const fix = vulnerability.fixAvailable;
            const fixAvailable = typeof fix === "boolean" ? fix : Boolean(fix);
            const fixVersion = typeof fix === "object" && fix !== null
                ? fix.version ?? null
                : null;
            const requiresMajorUpgrade = typeof fix === "object" &&
                fix !== null &&
                Boolean(fix.isSemVerMajor);
            const name = vulnerability.name || packageName;
            return {
                name,
                severity: vulnerability.severity || "unknown",
                isDirect: Boolean(vulnerability.isDirect),
                range: vulnerability.range || "Not specified",
                fixAvailable,
                fixVersion,
                requiresMajorUpgrade,
                description: descriptions.join("; ") || "No description provided.",
                advisoryUrl,
                introducedBy,
                affectedPackages: vulnerability.effects ?? [],
                installedLocations: vulnerability.nodes ?? [],
                remediation: getRemediation(fixAvailable, fixVersion, requiresMajorUpgrade),
            };
        });
        return {
            status: "completed",
            message: vulnerabilities.length
                ? "npm audit completed. Vulnerabilities were detected."
                : "npm audit completed. No vulnerable packages were reported.",
            summary: {
                total: counts.total ?? vulnerabilities.length,
                critical: counts.critical ?? 0,
                high: counts.high ?? 0,
                moderate: counts.moderate ?? 0,
                low: counts.low ?? 0,
                info: counts.info ?? 0,
            },
            vulnerabilities,
        };
    }
    catch {
        return {
            status: "unavailable",
            message: "npm audit returned data that could not be parsed.",
            summary: { ...emptySummary },
            vulnerabilities: [],
        };
    }
}
