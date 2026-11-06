
export type CompatibilityIssue = {
  severity: "error" | "warning" | "info";
  category: string;
  title: string;
  message: string;
};

export type CompatibilityCheck = {
  name: string;
  status: "passed" | "warning" | "failed";
  message: string;
};

type Dependencies = Record<string, string>;

type CompatibilityResult = {
  checks: CompatibilityCheck[];
  issues: CompatibilityIssue[];
};

type OverrideMap = Record<string, unknown>;

export function checkCompatibility(
  dependencies: Dependencies,
  overrides: unknown
): CompatibilityResult {
  const checks: CompatibilityCheck[] = [];
  const issues: CompatibilityIssue[] = [];

  const hasLocklift = Boolean(dependencies.locklift);

  const overrideMap: OverrideMap =
    overrides &&
    typeof overrides === "object" &&
    !Array.isArray(overrides)
      ? (overrides as OverrideMap)
      : {};

  // 1. Locklift version metadata check.
  if (hasLocklift) {
    const lockliftVersion = dependencies.locklift.trim();

    if (lockliftVersion === "2.9.9") {
      checks.push({
        name: "Locklift version metadata",
        status: "passed",
        message:
          "Locklift 2.9.9 package metadata has been reviewed. Its Nekoton dependency uses the nekoton-wasm-locklift alias.",
      });

      issues.push({
        severity: "info",
        category: "Version verification",
        title: "Locklift runtime compatibility not fully verified",
        message:
          "The package metadata for Locklift 2.9.9 is recognised, but this does not establish runtime compatibility with every compiler, SDK, or project configuration.",
      });
    } else {
      checks.push({
        name: "Locklift version metadata",
        status: "warning",
        message:
          `Detected Locklift ${lockliftVersion}. ` +
          "This version does not have a verified compatibility profile in the scanner.",
      });

      issues.push({
        severity: "info",
        category: "Version verification",
        title: "Locklift compatibility needs verification",
        message:
          `Detected version: ${lockliftVersion}. ` +
          "The scanner cannot currently confirm its complete compatibility with the detected project configuration.",
      });
    }
  }

  // 2. Locklift Nekoton WASM override check.
  if (hasLocklift) {
    const nekotonOverride = overrideMap["nekoton-wasm"];

    if (typeof nekotonOverride === "string") {
      const normalizedOverride = nekotonOverride.trim();

      if (
        normalizedOverride === "$nekoton-wasm" &&
        Boolean(dependencies["nekoton-wasm"])
      ) {
        checks.push({
          name: "Locklift Nekoton override",
          status: "passed",
          message:
            "The override references the project's direct nekoton-wasm dependency.",
        });
      } else if (
        /^npm:nekoton-wasm-locklift@.+$/i.test(normalizedOverride)
      ) {
        checks.push({
          name: "Locklift Nekoton override",
          status: "passed",
          message:
            `The Locklift Nekoton WASM alias is configured: ${normalizedOverride}. ` +
            "The selected version range has not been independently tested.",
        });

        issues.push({
          severity: "info",
          category: "SDK compatibility",
          title: "Nekoton WASM version range needs verification",
          message:
            "A Locklift-specific Nekoton alias is configured. Verify that its version range matches your installed Locklift release.",
        });
      } else {
        checks.push({
          name: "Locklift Nekoton override",
          status: "warning",
          message:
            "A Nekoton override exists, but it does not match a recognised Locklift configuration.",
        });

        issues.push({
          severity: "warning",
          category: "SDK compatibility",
          title: "Unrecognised Nekoton override",
          message:
            `Current override: ${normalizedOverride}. ` +
            "Review it against the requirements of your installed Locklift version.",
        });
      }
    } else {
      checks.push({
        name: "Locklift Nekoton override",
        status: "warning",
        message:
          "No root-level Nekoton override was found. Review the dependency configuration for your installed Locklift version.",
      });

      issues.push({
        severity: "warning",
        category: "SDK compatibility",
        title: "Locklift Nekoton override not configured",
        message:
          "Locklift documentation describes using the nekoton-wasm-locklift package through a package.json override. Requirements and recommended versions can differ between Locklift releases.",
      });
    }
  }

  // 3. Recognised SDK package detection.
  const recognizedPackages = [
    "@eversdk/core",
    "@eversdk/lib-node",
    "@eversdk/lib-web",
    "nekoton-wasm",
    "nekoton-wasm-locklift",
    "everscale-inpage-provider",
    "everscale-standalone-client",
  ];

  let detectedPackages = 0;

  for (const packageName of recognizedPackages) {
    const version = dependencies[packageName];

    if (!version) continue;

    detectedPackages++;

    checks.push({
      name: `${packageName} detection`,
      status: "warning",
      message:
        `Detected ${version}. ` +
        "The scanner has not yet verified this package's compatibility with the complete project toolchain.",
    });

    issues.push({
      severity: "info",
      category: "Version verification",
      title: `${packageName} compatibility unverified`,
      message:
        `Declared version: ${version}. ` +
        "A complete compatibility rule has not yet been established.",
    });
  }

  if (!hasLocklift && detectedPackages === 0) {
    checks.push({
      name: "SDK compatibility",
      status: "warning",
      message:
        "No recognised SDK packages were found for compatibility analysis.",
    });

    issues.push({
      severity: "info",
      category: "SDK",
      title: "No recognised SDK dependencies",
      message:
        "The scanner could not identify supported Venom or Everscale SDK packages in the detected dependencies.",
    });
  }

  return { checks, issues };
}
