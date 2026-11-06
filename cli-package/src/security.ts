
import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
import path from "node:path";

export type SecurityVulnerability = {
  name: string;
  severity: string;
  isDirect: boolean;
  range: string;
  fixAvailable: boolean;
  fixVersion: string | null;
  requiresMajorUpgrade: boolean;
  description: string;
  advisoryUrl: string | null;
  introducedBy: string[];
  affectedPackages: string[];
  installedLocations: string[];
  remediation: string;
};

export type SecurityAuditReport = {
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
};

type NpmAuditFix = {
  name?: string;
  version?: string;
  isSemVerMajor?: boolean;
};

type NpmAuditAdvisory = {
  title?: string;
  name?: string;
  range?: string;
  url?: string;
};

type NpmAuditVulnerability = {
  name?: string;
  severity?: string;
  isDirect?: boolean;
  range?: string;
  fixAvailable?: boolean | NpmAuditFix;
  via?: Array<string | NpmAuditAdvisory>;
  effects?: string[];
  nodes?: string[];
};

type NpmAuditData = {
  metadata?: {
    vulnerabilities?: {
      total?: number;
      critical?: number;
      high?: number;
      moderate?: number;
      low?: number;
      info?: number;
    };
  };
  vulnerabilities?: Record<string, NpmAuditVulnerability>;
};

const emptySummary = {
  total: 0,
  critical: 0,
  high: 0,
  moderate: 0,
  low: 0,
  info: 0,
};

function runNpmAudit(root: string): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      "npm",
      ["audit", "--json"],
      {
        cwd: root,
        encoding: "utf8",
        timeout: 120_000,
        maxBuffer: 10 * 1024 * 1024,
      },
      (error, stdout, stderr) => {
        // npm audit can exit with code 1 when vulnerabilities exist.
        // Its JSON output is still valid and should be processed.
        if (stdout && stdout.trim()) {
          resolve(stdout);
          return;
        }

        reject(
          new Error(
            stderr?.trim() ||
              error?.message ||
              "npm audit did not return a report."
          )
        );
      }
    );
  });
}

function getRemediation(
  fixAvailable: boolean,
  fixVersion: string | null,
  requiresMajorUpgrade: boolean
): string {
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

export async function scanSecurity(
  projectRoot: string
): Promise<SecurityAuditReport> {
  const lockfilePath = path.join(projectRoot, "package-lock.json");

  try {
    await access(lockfilePath);
  } catch {
    return {
      status: "skipped",
      message:
        "Security audit skipped because package-lock.json was not found. Generate an npm lockfile before running npm audit.",
      summary: { ...emptySummary },
      vulnerabilities: [],
    };
  }

  let output: string;

  try {
    output = await runNpmAudit(projectRoot);
  } catch (error) {
    return {
      status: "unavailable",
      message:
        error instanceof Error
          ? error.message
          : "Unable to run npm audit.",
      summary: { ...emptySummary },
      vulnerabilities: [],
    };
  }

  try {
    const data = JSON.parse(output) as NpmAuditData;
    const counts = data.metadata?.vulnerabilities ?? {};
    const rawVulnerabilities = data.vulnerabilities ?? {};

    const vulnerabilities: SecurityVulnerability[] = Object.entries(
      rawVulnerabilities
    ).map(([packageName, vulnerability]) => {
      const via = vulnerability.via ?? [];

      const advisories = via.filter(
        (item): item is NpmAuditAdvisory =>
          typeof item === "object" && item !== null
      );

      const introducedBy = via.filter(
        (item): item is string => typeof item === "string"
      );

      const descriptions = advisories
        .map((item) => item.title || item.name || "")
        .filter(Boolean);

      const advisoryUrl =
        advisories.find((item) => item.url)?.url ?? null;

      const fix = vulnerability.fixAvailable;

      const fixAvailable =
        typeof fix === "boolean" ? fix : Boolean(fix);

      const fixVersion =
        typeof fix === "object" && fix !== null
          ? fix.version ?? null
          : null;

      const requiresMajorUpgrade =
        typeof fix === "object" &&
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
        description:
          descriptions.join("; ") || "No description provided.",
        advisoryUrl,
        introducedBy,
        affectedPackages: vulnerability.effects ?? [],
        installedLocations: vulnerability.nodes ?? [],
        remediation: getRemediation(
          fixAvailable,
          fixVersion,
          requiresMajorUpgrade
        ),
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
  } catch {
    return {
      status: "unavailable",
      message: "npm audit returned data that could not be parsed.",
      summary: { ...emptySummary },
      vulnerabilities: [],
    };
  }
}
