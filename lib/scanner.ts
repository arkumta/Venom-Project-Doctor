
import { checkCompatibility } from "./compatibility";

export type ProjectFile = {
  path: string;
  content: string;
};

export type ScanIssue = {
  severity: "error" | "warning" | "info";
  category: string;
  title: string;
  message: string;
  file?: string;
};

export type ScanReport = {
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
  issues: ScanIssue[];
  scannedAt: string;
};

const normalizePath = (path: string) =>
  path.replace(/\\/g, "/").replace(/^\.\/+/, "");

const findFile = (files: ProjectFile[], name: string) =>
  files.find(
    (file) => normalizePath(file.path).split("/").pop() === name
  );

const isPlainObject = (
  value: unknown
): value is Record<string, unknown> =>
  typeof value === "object" &&
  value !== null &&
  !Array.isArray(value);

const getDependencyMap = (
  packageData: Record<string, unknown>
): Record<string, string> => {
  const result: Record<string, string> = {};

  for (const section of [
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
  ]) {
    const entries = packageData[section];

    if (!isPlainObject(entries)) continue;

    for (const [name, version] of Object.entries(entries)) {
      if (typeof version === "string") {
        result[name] = version;
      }
    }
  }

  return result;
};

const recognizedPackagePattern =
  /locklift|eversdk|nekoton|t-solidity|ton-solidity|everscale-inpage-provider|everscale-standalone-client|@ton\/(core|ton|crypto|sandbox)/i;

const hasCompilerSettings = (content: string) => {
  const patterns = [
    /\bsolcVersion\b/,
    /\bcompilerVersion\b/,
    /\bcompiler\b/,
    /\bcompilers\b/,
    /\bversion\s*:/,
    /\bsolc\b/,
    /\bevmVersion\b/,
    /\boptimizer\b/,
  ];

  return patterns.some((pattern) => pattern.test(content));
};

export function scanProject(files: ProjectFile[]): ScanReport {
  const issues: ScanIssue[] = [];
  const checks: ScanReport["checks"] = [];
  const tools: ScanReport["tools"] = [];

  const normalizedPaths = files.map((file) => ({
    ...file,
    normalizedPath: normalizePath(file.path),
  }));

  // Find and validate package.json.
  const packageFile = findFile(files, "package.json");

  let packageData: Record<string, unknown> = {};
  let packageValid = false;

  if (packageFile) {
    try {
      const parsed: unknown = JSON.parse(packageFile.content);

      if (isPlainObject(parsed)) {
        packageData = parsed;
        packageValid = true;
      } else {
        throw new Error("Invalid package manifest structure.");
      }
    } catch {
      issues.push({
        severity: "error",
        category: "Dependencies",
        title: "Invalid package.json",
        message:
          "The package.json file could not be parsed as a valid JSON object.",
        file: packageFile.path,
      });
    }
  } else {
    issues.push({
      severity: "warning",
      category: "Dependencies",
      title: "package.json not found",
      message:
        "No package manifest was found. This scanner currently uses package.json for Node.js SDK detection.",
    });
  }

  const dependencies = getDependencyMap(packageData);

  const detectedPackages = Object.keys(dependencies).filter((name) =>
    recognizedPackagePattern.test(name)
  );

  for (const name of detectedPackages) {
    tools.push({
      name,
      version: dependencies[name],
    });
  }

  checks.push({
    name: "Project manifest",
    status: packageValid ? "passed" : "failed",
    message: packageValid
      ? "A valid package.json was found."
      : "A valid package.json is required for this dependency analysis.",
  });

  checks.push({
    name: "Venom SDK detection",
    status: detectedPackages.length ? "passed" : "warning",
    message: detectedPackages.length
      ? `${detectedPackages.length} recognized ecosystem package(s) detected.`
      : "No recognized ecosystem packages detected. The project may use an unsupported SDK.",
  });

  if (!detectedPackages.length) {
    issues.push({
      severity: "warning",
      category: "SDK",
      title: "Venom tooling not detected",
      message:
        "No recognized Venom or supported TVM ecosystem development packages were found.",
    });
  }

  // Compatibility analysis.
  const compatibility = checkCompatibility(
    dependencies,
    packageData.overrides
  );

  checks.push(...compatibility.checks);
  issues.push(...compatibility.issues);

  // Detect Locklift configuration.
  const lockliftConfig = normalizedPaths.find((file) =>
    /(^|\/)locklift\.config\.(ts|js|cjs|mjs)$/.test(
      file.normalizedPath
    )
  );

  if (dependencies.locklift) {
    checks.push({
      name: "Locklift configuration",
      status: lockliftConfig ? "passed" : "warning",
      message: lockliftConfig
        ? `Configuration found: ${lockliftConfig.path}`
        : "Locklift is installed, but no recognized Locklift configuration was found.",
    });

    if (!lockliftConfig) {
      issues.push({
        severity: "warning",
        category: "Configuration",
        title: "Locklift configuration missing",
        message:
          "Locklift is listed as a dependency, but the scanner could not find locklift.config.ts, .js, .cjs or .mjs.",
      });
    } else {
      const configContent = lockliftConfig.content;

      if (!configContent.trim()) {
        issues.push({
          severity: "warning",
          category: "Configuration",
          title: "Locklift configuration is empty",
          message:
            "The Locklift configuration file exists but contains no configuration content.",
          file: lockliftConfig.path,
        });

        checks.push({
          name: "Locklift configuration content",
          status: "warning",
          message: "The detected configuration file is empty.",
        });
      } else {
        checks.push({
          name: "Locklift configuration content",
          status: "passed",
          message:
            "The detected Locklift configuration file contains content. Full runtime validity has not been verified.",
        });
      }
    }
  } else {
    checks.push({
      name: "Locklift configuration",
      status: "passed",
      message:
        "Locklift is not declared as a dependency. A Locklift configuration is not required for every project.",
    });
  }

  // Detect Solidity and Leo files.
  const solidityFiles = normalizedPaths.filter((file) =>
    /\.(sol|t\.sol)$/i.test(file.normalizedPath)
  );

  const leoFiles = normalizedPaths.filter((file) =>
    /\.leo$/i.test(file.normalizedPath)
  );

  const hasLocklift = Boolean(dependencies.locklift);
  const hasTvmPackages = detectedPackages.some((name) =>
    /locklift|eversdk|nekoton|everscale/i.test(name)
  );

  const hasTonPackages = detectedPackages.some((name) =>
    /^@ton\//i.test(name)
  );

  let projectType = "Unknown project";

  if (leoFiles.length > 0) {
    projectType = "Leo project";
  } else if (solidityFiles.length > 0 && hasLocklift) {
    projectType = "Solidity / TVM project";
  } else if (solidityFiles.length > 0 && hasTvmPackages) {
    projectType = "Solidity / TVM ecosystem project";
  } else if (solidityFiles.length > 0 && hasTonPackages) {
    projectType = "Solidity / TON project";
  } else if (solidityFiles.length > 0) {
    projectType = "Solidity project (ecosystem unverified)";
  } else if (detectedPackages.length > 0) {
    projectType = "Blockchain development project";
  }

  checks.push({
    name: "Smart contract source files",
    status:
      solidityFiles.length || leoFiles.length ? "passed" : "warning",
    message: solidityFiles.length
      ? `${solidityFiles.length} Solidity source file(s) found.`
      : leoFiles.length
        ? `${leoFiles.length} Leo source file(s) found.`
        : "No recognized Solidity or Leo source files found.",
  });

  // Detect known compiler configuration files.
  const compilerConfigNames =
    /(^|\/)(tvm\.config\.json|solc\.json|\.solcover\.js|hardhat\.config\.(ts|js|cjs|mjs)|foundry\.toml|truffle-config\.(js|ts)|truffle\.config\.(js|ts))$/i;

  const compilerConfigs = normalizedPaths.filter((file) =>
    compilerConfigNames.test(file.normalizedPath)
  );

  const lockliftHasCompilerSettings =
    lockliftConfig && hasCompilerSettings(lockliftConfig.content);

  const standaloneCompilerConfig = compilerConfigs.find((file) =>
    hasCompilerSettings(file.content)
  );

  const compilerConfig = standaloneCompilerConfig ||
    (lockliftHasCompilerSettings ? lockliftConfig : undefined);

  const hasSolidityOrLocklift =
    solidityFiles.length > 0 || hasLocklift;

  if (compilerConfig) {
    checks.push({
      name: "Compiler configuration",
      status: "passed",
      message: `Compiler-related settings detected in ${compilerConfig.path}. The scanner has not executed the compiler or verified the settings.`,
    });
  } else if (hasSolidityOrLocklift) {
    checks.push({
      name: "Compiler configuration",
      status: "warning",
      message:
        "No recognized compiler settings were detected in the selected configuration files.",
    });

    issues.push({
      severity: "info",
      category: "Compiler configuration",
      title: "Compiler settings not verified",
      message:
        "The scanner could not identify recognized compiler settings. Some projects define compiler settings through scripts or external configuration, so this is not proof that compiler configuration is missing.",
    });
  } else {
    checks.push({
      name: "Compiler configuration",
      status: "passed",
      message:
        "Compiler configuration is not required for the detected project files.",
    });
  }

  // Environment files are optional. Their contents are never inspected.
  const envFiles = normalizedPaths.filter((file) =>
    /(^|\/)\.env(\..+)?$/i.test(
      file.normalizedPath.split("/").pop() || ""
    )
  );

  checks.push({
    name: "Environment configuration",
    status: "passed",
    message: envFiles.length
      ? "An environment file was supplied. Its contents were not inspected."
      : "No environment file supplied. Environment files are optional and may be excluded from scanning.",
  });

  // Basic source inspection. These are heuristic signals, not proof of
  // vulnerabilities or compiler errors.
  const sourceFiles = solidityFiles;

  const sourceRules = [
    {
      pattern: /\btx\.origin\b/,
      title: "tx.origin usage detected",
      message:
        "tx.origin is used in this source file. Review whether it is being used for authorization, as this can create phishing-related security risks.",
    },
    {
      pattern: /\bdelegatecall\s*\(/,
      title: "delegatecall usage detected",
      message:
        "delegatecall is used in this source file. Review the target address, storage layout and access controls carefully.",
    },
    {
      pattern: /\bselfdestruct\s*\(/,
      title: "selfdestruct usage detected",
      message:
        "selfdestruct is used in this source file. Review its intended behavior and the semantics of your target EVM or TVM environment.",
    },
  ];

  for (const file of sourceFiles) {
    for (const rule of sourceRules) {
      if (rule.pattern.test(file.content)) {
        issues.push({
          severity: "info",
          category: "Smart contract review",
          title: rule.title,
          message:
            `${rule.message} This is a heuristic finding and requires manual review.`,
          file: file.path,
        });
      }
    }
  }

  checks.push({
    name: "Basic source pattern review",
    status: "passed",
    message: sourceFiles.length
      ? `Reviewed ${sourceFiles.length} Solidity source file(s) for selected risky patterns. This is not a complete static analysis.`
      : "No Solidity files were available for this heuristic review.",
  });

  const projectName =
    typeof packageData.name === "string" &&
    packageData.name.trim().length > 0
      ? packageData.name
      : "Unnamed project";

  // Calculate summary from check statuses.
  const totalChecks = checks.length;

  const passed = checks.filter(
    (check) => check.status === "passed"
  ).length;

  const warnings = checks.filter(
    (check) => check.status === "warning"
  ).length;

  const errors = checks.filter(
    (check) => check.status === "failed"
  ).length;

  const totalPoints = checks.reduce((total, check) => {
    if (check.status === "passed") return total + 100;
    if (check.status === "warning") return total + 50;
    return total;
  }, 0);

  const healthScore =
    totalChecks > 0
      ? Math.round(totalPoints / totalChecks)
      : 0;

  return {
    projectName,
    projectType,
    healthScore,
    summary: {
      totalChecks,
      passed,
      warnings,
      errors,
    },
    tools,
    checks,
    issues,
    scannedAt: new Date().toISOString(),
  };
}
