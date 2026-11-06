
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

const normalizePath = (path: string) => path.replace(/\\/g, "/");

const findFile = (files: ProjectFile[], name: string) =>
  files.find((file) => normalizePath(file.path).split("/").pop() === name);

const getObject = (value: unknown): Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};

export function scanProject(files: ProjectFile[]): ScanReport {
  const issues: ScanIssue[] = [];
  const checks: ScanReport["checks"] = [];
  const tools: ScanReport["tools"] = [];

  const normalizedPaths = files.map((file) => ({
    ...file,
    normalizedPath: normalizePath(file.path),
  }));

  const packageFile = findFile(files, "package.json");

  let packageData: Record<string, unknown> = {};
  let packageValid = false;

  if (packageFile) {
    try {
      const parsed: unknown = JSON.parse(packageFile.content);

      if (
        typeof parsed === "object" &&
        parsed !== null &&
        !Array.isArray(parsed)
      ) {
        packageData = parsed as Record<string, unknown>;
        packageValid = true;
      }
    } catch {
      issues.push({
        severity: "error",
        category: "Dependencies",
        title: "Invalid package.json",
        message: "The package.json file contains invalid JSON.",
        file: packageFile.path,
      });
    }
  } else {
    issues.push({
      severity: "warning",
      category: "Dependencies",
      title: "package.json not found",
      message: "No package manifest was found.",
    });
  }

  const dependencies: Record<string, string> = {
    ...Object.fromEntries(
      Object.entries(getObject(packageData.dependencies)).filter(
        (entry): entry is [string, string] => typeof entry[1] === "string"
      )
    ),
    ...Object.fromEntries(
      Object.entries(getObject(packageData.devDependencies)).filter(
        (entry): entry is [string, string] => typeof entry[1] === "string"
      )
    ),
    ...Object.fromEntries(
      Object.entries(getObject(packageData.peerDependencies)).filter(
        (entry): entry is [string, string] => typeof entry[1] === "string"
      )
    ),
  };

  const detectedPackages = Object.keys(dependencies).filter((name) =>
    /locklift|eversdk|nekoton|t-solidity|ton-solidity|everscale-inpage-provider|everscale-standalone-client/i.test(
      name
    )
  );

  for (const name of detectedPackages) {
    tools.push({ name, version: dependencies[name] });
  }

  checks.push({
    name: "Project manifest",
    status: packageValid ? "passed" : "failed",
    message: packageValid
      ? "A valid package.json was found."
      : "A valid package.json is required.",
  });

  checks.push({
    name: "Venom SDK detection",
    status: detectedPackages.length ? "passed" : "warning",
    message: detectedPackages.length
      ? `${detectedPackages.length} recognized package(s) detected.`
      : "No recognized Venom ecosystem packages detected.",
  });

  if (!detectedPackages.length) {
    issues.push({
      severity: "warning",
      category: "SDK",
      title: "Venom tooling not detected",
      message: "No recognized Venom development packages were found.",
    });
  }

  const compatibility = checkCompatibility(
    dependencies,
    packageData.overrides
  );

  checks.push(...compatibility.checks);
  issues.push(...compatibility.issues);

  const lockliftConfig = normalizedPaths.find((file) =>
    /(^|\/)locklift\.config\.(ts|js|cjs|mjs)$/.test(file.normalizedPath)
  );

  checks.push({
    name: "Locklift configuration",
    status: lockliftConfig ? "passed" : "warning",
    message: lockliftConfig
      ? `Configuration found: ${lockliftConfig.path}`
      : "No recognized Locklift configuration found.",
  });

  if (!lockliftConfig && dependencies.locklift) {
    issues.push({
      severity: "warning",
      category: "Configuration",
      title: "Locklift configuration missing",
      message:
        "Locklift is installed, but no recognized locklift.config file was found.",
    });
  }

  // Inspect compiler and linker settings in the Locklift config.
  if (lockliftConfig) {
    const compilerConfigured =
      /\bcompiler\s*:\s*\{[\s\S]*?\b(path|version)\s*:/.test(
        lockliftConfig.content
      );

    const linkerConfigured =
      /\blinker\s*:\s*\{[\s\S]*?\b(path|lib|version)\s*:/.test(
        lockliftConfig.content
      );

    checks.push({
      name: "Locklift compiler settings",
      status: compilerConfigured ? "passed" : "warning",
      message: compilerConfigured
        ? "Compiler settings were found in the Locklift configuration."
        : "No recognizable compiler path or version was found in the Locklift configuration.",
    });

    if (!compilerConfigured) {
      issues.push({
        severity: "warning",
        category: "Compiler",
        title: "Locklift compiler settings not detected",
        message:
          "Review the compiler section in locklift.config. The scanner uses static text detection and may not recognize every valid configuration style.",
        file: lockliftConfig.path,
      });
    }

    checks.push({
      name: "Locklift linker settings",
      status: linkerConfigured ? "passed" : "warning",
      message: linkerConfigured
        ? "Linker settings were found in the Locklift configuration."
        : "No recognizable linker path, library, or version was found in the Locklift configuration.",
    });

    if (!linkerConfigured) {
      issues.push({
        severity: "info",
        category: "Linker",
        title: "Locklift linker settings not detected",
        message:
          "Check whether your project needs explicit linker settings. Some project configurations may not require them.",
        file: lockliftConfig.path,
      });
    }
  }

  const solidityFiles = normalizedPaths.filter((file) =>
    /\.(sol|t\.sol)$/i.test(file.normalizedPath)
  );

  const leoFiles = normalizedPaths.filter((file) =>
    /\.leo$/i.test(file.normalizedPath)
  );

  const projectType =
    solidityFiles.length > 0
      ? "Solidity / TVM project"
      : leoFiles.length > 0
        ? "Leo project"
        : detectedPackages.length > 0
          ? "Venom development project"
          : "Unknown project";

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

  const compilerConfig = normalizedPaths.find((file) =>
    /(^|\/)(tvm\.config\.json|solc\.json|\.solcover\.js)$/i.test(
      file.normalizedPath
    )
  );

  checks.push({
    name: "Compiler configuration",
    status: compilerConfig ? "passed" : "warning",
    message: compilerConfig
      ? `Potential compiler configuration found: ${compilerConfig.path}`
      : "No recognized standalone compiler configuration found.",
  });

  const engines = getObject(packageData.engines);
  const nodeRequirement =
    typeof engines.node === "string" ? engines.node : null;

  checks.push({
    name: "Node.js version requirement",
    status: nodeRequirement ? "passed" : "warning",
    message: nodeRequirement
      ? `Node.js requirement declared: ${nodeRequirement}`
      : "No Node.js version requirement declared in package.json.",
  });

  if (!nodeRequirement) {
    issues.push({
      severity: "info",
      category: "Environment",
      title: "Node.js requirement not declared",
      message:
        "Consider adding an engines.node field to package.json so developers know which Node.js versions the project expects.",
    });
  }

  const lockfiles = [
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
  ];

  const foundLockfiles = lockfiles.filter((name) =>
    normalizedPaths.some(
      (file) => file.normalizedPath.split("/").pop() === name
    )
  );

  const packageManager =
    typeof packageData.packageManager === "string"
      ? packageData.packageManager
      : null;

  const multipleLockfiles = foundLockfiles.length > 1;

  checks.push({
    name: "Package manager consistency",
    status: multipleLockfiles ? "warning" : "passed",
    message: multipleLockfiles
      ? `Multiple lockfiles detected: ${foundLockfiles.join(", ")}.`
      : foundLockfiles.length
        ? `Lockfile detected: ${foundLockfiles[0]}.`
        : "No package manager lockfile detected.",
  });

  if (multipleLockfiles) {
    issues.push({
      severity: "warning",
      category: "Dependencies",
      title: "Multiple package manager lockfiles",
      message:
        "Multiple lockfiles can cause inconsistent dependency installations. Keep only the lockfile for your chosen package manager.",
    });
  }


  // Check whether Locklift configuration exists without its dependency.
  const hasLockliftConfig = Boolean(lockliftConfig);
  const hasLockliftDependency = Boolean(dependencies.locklift);

  if (hasLockliftConfig && !hasLockliftDependency) {
    checks.push({
      name: "Required Locklift dependency",
      status: "warning",
      message:
        "A Locklift configuration exists, but Locklift is not declared in package.json.",
    });

    issues.push({
      severity: "warning",
      category: "Dependencies",
      title: "Locklift dependency missing",
      message:
        "The project has a Locklift configuration but does not declare Locklift in its dependencies or devDependencies.",
    });
  } else if (hasLockliftConfig && hasLockliftDependency) {
    checks.push({
      name: "Required Locklift dependency",
      status: "passed",
      message: "Locklift is declared in package.json.",
    });
  }

  // Check npm package-lock.json consistency independently.
  const npmLockFile = normalizedPaths.find(
    (file) => file.normalizedPath === "package-lock.json"
  );

  if (npmLockFile) {
    try {
      const lockData: unknown = JSON.parse(npmLockFile.content);
      const lockObject = getObject(lockData);
      const lockPackages = getObject(lockObject.packages);
      const rootLockPackage = getObject(lockPackages[""]);

      const manifestDependencies = {
        ...getObject(packageData.dependencies),
        ...getObject(packageData.devDependencies),
        ...getObject(packageData.optionalDependencies),
      };

      const lockedDependencies = {
        ...getObject(rootLockPackage.dependencies),
        ...getObject(rootLockPackage.devDependencies),
        ...getObject(rootLockPackage.optionalDependencies),
      };

      const manifestNames = Object.keys(manifestDependencies);

      const missingFromLock = manifestNames.filter(
        (name) => !(name in lockedDependencies)
      );

      const extraInLock = Object.keys(lockedDependencies).filter(
        (name) => !(name in manifestDependencies)
      );

      const mismatchedSpecs = manifestNames.filter((name) => {
        if (!(name in lockedDependencies)) return false;
        return manifestDependencies[name] !== lockedDependencies[name];
      });

      const hasMismatch =
        missingFromLock.length > 0 ||
        extraInLock.length > 0 ||
        mismatchedSpecs.length > 0;

      checks.push({
        name: "npm lockfile consistency",
        status: hasMismatch ? "warning" : "passed",
        message: hasMismatch
          ? "The root package-lock.json dependency declarations differ from package.json."
          : "Root dependency declarations match between package.json and package-lock.json.",
      });

      if (hasMismatch) {
        issues.push({
          severity: "warning",
          category: "Dependencies",
          title: "Package manifest and lockfile differ",
          message: [
            missingFromLock.length
              ? `Missing from lockfile: ${missingFromLock.join(", ")}.`
              : "",
            extraInLock.length
              ? `Extra in lockfile: ${extraInLock.join(", ")}.`
              : "",
            mismatchedSpecs.length
              ? `Different version specifications: ${mismatchedSpecs.join(", ")}.`
              : "",
          ]
            .filter(Boolean)
            .join(" "),
          file: npmLockFile.path,
        });
      }
    } catch {
      checks.push({
        name: "npm lockfile consistency",
        status: "failed",
        message: "The package-lock.json file contains invalid JSON.",
      });

      issues.push({
        severity: "error",
        category: "Dependencies",
        title: "Invalid npm lockfile",
        message:
          "The package-lock.json file could not be parsed. Regenerate or repair the lockfile.",
        file: npmLockFile.path,
      });
    }
  }

  // Check package manager declaration against its lockfile.
  if (packageManager && foundLockfiles.length) {
    const declaredManager = packageManager.split("@")[0];

    const expectedLockfile: Record<string, string> = {
      npm: "package-lock.json",
      yarn: "yarn.lock",
      pnpm: "pnpm-lock.yaml",
      bun: foundLockfiles.includes("bun.lock")
        ? "bun.lock"
        : "bun.lockb",
    };

    const expected = expectedLockfile[declaredManager];

    if (expected && !foundLockfiles.includes(expected)) {
      issues.push({
        severity: "warning",
        category: "Dependencies",
        title: "Package manager mismatch",
        message: `package.json declares ${packageManager}, but its expected lockfile (${expected}) was not found.`,
      });
    }
  }


  const envFiles = normalizedPaths.filter((file) =>
    /(^|\/)\.env(\..+)?$/i.test(file.normalizedPath)
  );

  checks.push({
    name: "Environment configuration",
    status: envFiles.length ? "passed" : "warning",
    message: envFiles.length
      ? "Environment file detected. Its contents were not inspected."
      : "No environment file found. This may be intentional.",
  });

  const projectName =
    typeof packageData.name === "string"
      ? packageData.name
      : "Unnamed project";

  const totalChecks = checks.length;
  const passed = checks.filter((item) => item.status === "passed").length;
  const warnings = checks.filter(
    (item) => item.status === "warning"
  ).length;
  const errors = checks.filter(
    (item) => item.status === "failed"
  ).length;

  const totalPoints = checks.reduce((total, check) => {
    if (check.status === "passed") return total + 100;
    if (check.status === "warning") return total + 50;
    return total;
  }, 0);

  const healthScore =
    totalChecks > 0 ? Math.round(totalPoints / totalChecks) : 0;

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
