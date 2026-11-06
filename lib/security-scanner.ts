
import type { ProjectFile } from "./scanner";

export type SecurityVulnerability = {
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
  scannedPackages: number;
};

type InstalledPackage = {
  name: string;
  version: string;
  isDirect: boolean;
  locations: string[];
  parentPackage: string | null;
  dependencyChain: string[];
};

type OsvBatchResult = {
  vulns?: { id: string }[];
};

type OsvBatchResponse = {
  results?: OsvBatchResult[];
};

type OsvVulnerability = {
  id: string;
  summary?: string;
  details?: string;
  severity?: {
    type?: string;
    score?: string;
  }[];
  database_specific?: {
    severity?: string;
  };
  affected?: {
    package?: {
      name?: string;
    };
    ranges?: {
      events?: {
        introduced?: string;
        fixed?: string;
      }[];
    }[];
    versions?: string[];
  }[];
  references?: {
    type?: string;
    url?: string;
  }[];
};

type OsvQueryHit = {
  id: string;
  packageName: string;
  version: string;
};

const emptySummary = {
  total: 0,
  critical: 0,
  high: 0,
  moderate: 0,
  low: 0,
  info: 0,
};

function unavailable(message: string): SecurityAuditReport {
  return {
    status: "unavailable",
    message,
    summary: { ...emptySummary },
    vulnerabilities: [],
    scannedPackages: 0,
  };
}

function skipped(message: string): SecurityAuditReport {
  return {
    status: "skipped",
    message,
    summary: { ...emptySummary },
    vulnerabilities: [],
    scannedPackages: 0,
  };
}

function getPackageName(location: string): string | null {
  const parts = location.split("/");
  const index = parts.lastIndexOf("node_modules");

  if (index === -1 || !parts[index + 1]) {
    return null;
  }

  if (parts[index + 1].startsWith("@")) {
    if (!parts[index + 2]) return null;

    return `${parts[index + 1]}/${parts[index + 2]}`;
  }

  return parts[index + 1];
}

function getSeverity(
  vulnerability: OsvVulnerability
): SecurityVulnerability["severity"] {
  const databaseSeverity =
    vulnerability.database_specific?.severity?.toLowerCase();

  if (databaseSeverity) {
    if (databaseSeverity.includes("critical")) return "critical";
    if (databaseSeverity.includes("high")) return "high";

    if (
      databaseSeverity.includes("moderate") ||
      databaseSeverity.includes("medium")
    ) {
      return "moderate";
    }

    if (databaseSeverity.includes("low")) return "low";
  }

  // CVSS scores can be numeric strings, for example "8.5".
  const scoreString = vulnerability.severity?.find(
    (item) => item.score && /^\d+(\.\d+)?$/.test(item.score)
  )?.score;

  if (scoreString) {
    const score = Number(scoreString);

    if (score >= 9) return "critical";
    if (score >= 7) return "high";
    if (score >= 4) return "moderate";
    if (score > 0) return "low";
  }

  return "unknown";
}

function getAffectedRange(
  vulnerability: OsvVulnerability,
  packageName: string
): string {
  const affected = vulnerability.affected?.find(
    (item) => item.package?.name === packageName
  );

  if (!affected) {
    return "Affected version not specified.";
  }

  const ranges = affected.ranges
    ?.flatMap((range) =>
      (range.events ?? []).map((event) => {
        if (
          event.introduced !== undefined &&
          event.fixed !== undefined
        ) {
          return `${event.introduced} to before ${event.fixed}`;
        }

        if (event.introduced !== undefined) {
          return `Introduced in ${event.introduced}`;
        }

        if (event.fixed !== undefined) {
          return `Fixed in ${event.fixed}`;
        }

        return "";
      })
    )
    .filter(Boolean);

  return (
    ranges?.join("; ") ||
    "See advisory for affected versions."
  );
}

function getFixedVersions(
  vulnerability: OsvVulnerability,
  packageName: string
): string[] {
  const affected = vulnerability.affected?.find(
    (item) => item.package?.name === packageName
  );

  return Array.from(
    new Set(
      affected?.ranges?.flatMap((range) =>
        (range.events ?? [])
          .map((event) => event.fixed)
          .filter((version): version is string => Boolean(version))
      ) ?? []
    )
  );
}
function getRemediation(fixedVersions: string[]): string {
  if (fixedVersions.length > 0) {
    return `A fix is listed in version ${fixedVersions.join(
      ", "
    )}. Review the release notes and test your project before upgrading.`;
  }

  return "No fixed version was identified in the advisory. Review the security advisory and consider upgrading or replacing the affected dependency.";
}
function getUpgradeRisk(
  currentVersion: string,
  fixedVersions: string[]
): "patch" | "minor" | "major" | "unknown" {
  if (!fixedVersions.length) return "unknown";

  const current = currentVersion.match(
    /^\D*(\d+)\.(\d+)\.(\d+)/
  );

  const fixed = fixedVersions[0].match(
    /^\D*(\d+)\.(\d+)\.(\d+)/
  );

  if (!current || !fixed) return "unknown";

  const currentMajor = Number(current[1]);
  const currentMinor = Number(current[2]);
  const currentPatch = Number(current[3]);

  const fixedMajor = Number(fixed[1]);
  const fixedMinor = Number(fixed[2]);
  const fixedPatch = Number(fixed[3]);

  if (fixedMajor > currentMajor) return "major";

  if (
    fixedMajor === currentMajor &&
    fixedMinor > currentMinor
  ) {
    return "minor";
  }

  if (
    fixedMajor === currentMajor &&
    fixedMinor === currentMinor &&
    fixedPatch > currentPatch
  ) {
    return "patch";
  }

  return "unknown";
}

function extractPackages(
  lockfile: Record<string, unknown>,
  manifest: Record<string, unknown>
): InstalledPackage[] {
  const rawPackages = lockfile.packages;

  if (
    typeof rawPackages !== "object" ||
    rawPackages === null ||
    Array.isArray(rawPackages)
  ) {
    return [];
  }

  const packageEntries = rawPackages as Record<string, unknown>;
  const rootPackage = packageEntries[""];

  const rootData =
    typeof rootPackage === "object" &&
    rootPackage !== null &&
    !Array.isArray(rootPackage)
      ? (rootPackage as Record<string, unknown>)
      : {};

  const dependencyGroups = [
    manifest.dependencies,
    manifest.devDependencies,
    manifest.optionalDependencies,
    rootData.dependencies,
    rootData.devDependencies,
    rootData.optionalDependencies,
  ];

  const directNames = new Set<string>();

  for (const group of dependencyGroups) {
    if (
      typeof group !== "object" ||
      group === null ||
      Array.isArray(group)
    ) {
      continue;
    }

    Object.keys(group).forEach((name) => directNames.add(name));
  }

  const packageLocations = Object.keys(packageEntries).filter(
    (location) => location.includes("node_modules/")
  );

  const installed = new Map<string, InstalledPackage>();

  for (const location of packageLocations) {
    const rawPackage = packageEntries[location];

    if (
      typeof rawPackage !== "object" ||
      rawPackage === null ||
      Array.isArray(rawPackage)
    ) {
      continue;
    }

    const packageData = rawPackage as Record<string, unknown>;
    const name = getPackageName(location);

    if (
      !name ||
      typeof packageData.version !== "string" ||
      !packageData.version.trim()
    ) {
      continue;
    }

    const version = packageData.version.trim();
    const key = `${name}@${version}`;

    // A direct dependency must be installed at the root package location.
    // A nested copy of the same package is not automatically direct.
    const isDirect =
      location === `node_modules/${name}` &&
      directNames.has(name);

    // Find the nearest physically nested installed package.
    // This is useful context, but does not prove the logical dependency
    // relationship when npm has hoisted packages.
    const parentLocations = packageLocations
      .filter(
        (candidate) =>
          candidate !== location &&
          location.startsWith(`${candidate}/node_modules/`)
      )
      .sort((a, b) => b.length - a.length);

    const nearestParentLocation = parentLocations[0] ?? null;
    const parentPackage = nearestParentLocation
      ? getPackageName(nearestParentLocation)
      : null;

    const dependencyChain = parentPackage
      ? [parentPackage, name]
      : [name];

    const existing = installed.get(key);

    if (existing) {
      existing.locations.push(location);

      if (
        !existing.parentPackage &&
        parentPackage
      ) {
        existing.parentPackage = parentPackage;
        existing.dependencyChain = dependencyChain;
      }

      existing.isDirect = existing.isDirect || isDirect;
    } else {
      installed.set(key, {
        name,
        version,
        isDirect,
        locations: [location],
        parentPackage,
        dependencyChain,
      });
    }
  }

  return Array.from(installed.values());
}

async function fetchOsvBatch(
  packages: InstalledPackage[]
): Promise<OsvQueryHit[]> {
  const hits: OsvQueryHit[] = [];

  // OSV supports batch queries. Process up to 1,000 packages per request.
  for (let i = 0; i < packages.length; i += 1000) {
    const batch = packages.slice(i, i + 1000);

    const response = await fetch(
      "https://api.osv.dev/v1/querybatch",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          queries: batch.map((item) => ({
            package: {
              name: item.name,
              ecosystem: "npm",
            },
            version: item.version,
          })),
        }),
        signal: AbortSignal.timeout(25000),
        cache: "no-store",
      }
    );

    if (!response.ok) {
      throw new Error(
        `OSV vulnerability lookup failed (HTTP ${response.status}).`
      );
    }

    const data = (await response.json()) as OsvBatchResponse;

    if (
      !Array.isArray(data.results) ||
      data.results.length !== batch.length
    ) {
      throw new Error("OSV returned an unexpected batch response.");
    }

    // Preserve the exact package and version for each OSV result.
    data.results.forEach((result, index) => {
      const installed = batch[index];

      for (const vulnerability of result.vulns ?? []) {
        if (!vulnerability.id) continue;

        hits.push({
          id: vulnerability.id,
          packageName: installed.name,
          version: installed.version,
        });
      }
    });
  }

  // Remove duplicate advisory/package/version combinations.
  return Array.from(
    new Map(
      hits.map((hit) => [
        `${hit.id}:${hit.packageName}:${hit.version}`,
        hit,
      ])
    ).values()
  );
}

async function fetchVulnerability(
  id: string
): Promise<OsvVulnerability> {
  const response = await fetch(
    `https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`,
    {
      signal: AbortSignal.timeout(15000),
      cache: "no-store",
    }
  );

  if (!response.ok) {
    throw new Error(`Unable to retrieve advisory ${id}.`);
  }

  return (await response.json()) as OsvVulnerability;
}

async function fetchVulnerabilityDetails(
  ids: string[]
): Promise<OsvVulnerability[]> {
  const results: OsvVulnerability[] = [];

  // Limit concurrent requests to avoid overwhelming the API.
  for (let i = 0; i < ids.length; i += 10) {
    const batch = ids.slice(i, i + 10);

    const details = await Promise.all(
      batch.map((id) => fetchVulnerability(id))
    );

    results.push(...details);
  }

  return results;
}

export async function scanSecurity(
  files: ProjectFile[]
): Promise<SecurityAuditReport> {
  const lockfile = files.find(
    (file) =>
      file.path.replace(/\\/g, "/").split("/").pop() ===
      "package-lock.json"
  );

  if (!lockfile) {
    return skipped(
      "Security audit skipped because package-lock.json was not uploaded."
    );
  }

  let lockData: Record<string, unknown>;

  try {
    const parsed = JSON.parse(lockfile.content);

    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      return skipped(
        "The package-lock.json file has an invalid structure."
      );
    }

    lockData = parsed as Record<string, unknown>;
  } catch {
    return skipped(
      "The package-lock.json file contains invalid JSON."
    );
  }

  if (![2, 3].includes(Number(lockData.lockfileVersion))) {
    return skipped(
      "Only npm package-lock.json versions 2 and 3 are currently supported."
    );
  }

  const manifestFile = files.find(
    (file) =>
      file.path.replace(/\\/g, "/").split("/").pop() ===
      "package.json"
  );

  let manifest: Record<string, unknown> = {};

  if (manifestFile) {
    try {
      const parsed = JSON.parse(manifestFile.content);

      if (
        typeof parsed === "object" &&
        parsed !== null &&
        !Array.isArray(parsed)
      ) {
        manifest = parsed as Record<string, unknown>;
      }
    } catch {
      return skipped(
        "The package.json file is invalid. Unable to identify direct dependencies."
      );
    }
  }

  const packages = extractPackages(lockData, manifest);

  if (!packages.length) {
    return skipped(
      "No installed npm dependencies were found in the lockfile."
    );
  }

  try {
    // Each hit retains the exact version OSV identified as vulnerable.
    const hits = await fetchOsvBatch(packages);

    if (!hits.length) {
      return {
        status: "completed",
        message:
          "Security lookup completed. No known vulnerabilities were returned for the scanned package versions.",
        summary: { ...emptySummary },
        vulnerabilities: [],
        scannedPackages: packages.length,
      };
    }

    const ids = Array.from(
      new Set(hits.map((hit) => hit.id))
    );

    const details = await fetchVulnerabilityDetails(ids);

    const advisoryMap = new Map(
      details.map((advisory) => [advisory.id, advisory])
    );

    const vulnerabilities: SecurityVulnerability[] = [];

    for (const hit of hits) {
      const advisory = advisoryMap.get(hit.id);

      if (!advisory) continue;

      const affected = advisory.affected?.find(
        (item) => item.package?.name === hit.packageName
      );

      if (!affected) continue;

      const installed = packages.find(
        (item) =>
          item.name === hit.packageName &&
          item.version === hit.version
      );

      if (!installed) continue;

      const references = advisory.references ?? [];

      const advisoryUrl =
        references.find((reference) =>
          ["ADVISORY", "WEB"].includes(reference.type ?? "")
        )?.url ??
        references[0]?.url ??
        null;

      const fixedVersions = getFixedVersions(
        advisory,
        hit.packageName
      );

vulnerabilities.push({
  id: advisory.id,
  name: hit.packageName,
  version: hit.version,
  severity: getSeverity(advisory),
  isDirect: installed.isDirect,

  summary:
    advisory.summary ||
    advisory.details?.slice(0, 500) ||
    "Security advisory reported for this dependency.",

  affectedRange: getAffectedRange(
    advisory,
    hit.packageName
  ),

  fixedVersions,
  advisoryUrl,

  locations: installed.locations,

  remediation: getRemediation(fixedVersions),

  nearestNestedPackage: installed.parentPackage,
  dependencyChain: installed.dependencyChain,

  suggestedCommand:
    installed.isDirect && fixedVersions.length > 0
      ? `npm install ${hit.packageName}@${fixedVersions[0]}`
      : null,

  upgradeRisk: getUpgradeRisk(
    hit.version,
    fixedVersions
  ),
});
    }

    const uniqueVulnerabilities = Array.from(
      new Map(
        vulnerabilities.map((item) => [
          `${item.id}:${item.name}:${item.version}`,
          item,
        ])
      ).values()
    );

    const summary = {
      total: uniqueVulnerabilities.length,
      critical: uniqueVulnerabilities.filter(
        (item) => item.severity === "critical"
      ).length,
      high: uniqueVulnerabilities.filter(
        (item) => item.severity === "high"
      ).length,
      moderate: uniqueVulnerabilities.filter(
        (item) => item.severity === "moderate"
      ).length,
      low: uniqueVulnerabilities.filter(
        (item) => item.severity === "low"
      ).length,
      info: uniqueVulnerabilities.filter(
        (item) => item.severity === "unknown"
      ).length,
    };

    return {
      status: "completed",
      message: uniqueVulnerabilities.length
        ? "Security audit completed. Known vulnerabilities were detected."
        : "Security lookup completed. No known vulnerabilities were returned for the scanned package versions.",
      summary,
      vulnerabilities: uniqueVulnerabilities,
      scannedPackages: packages.length,
    };
  } catch (error) {
    return unavailable(
      error instanceof Error
        ? error.message
        : "Unable to complete the security audit."
    );
  }
}
