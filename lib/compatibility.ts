
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

const recognizedPackages = [
  "locklift",
  "@eversdk/core",
  "@eversdk/lib-node",
  "@eversdk/lib-web",
  "nekoton-wasm",
  "nekoton-wasm-locklift",
  "everscale-inpage-provider",
  "everscale-standalone-client",
  "ton",
  "@ton/core",
  "@ton/ton",
  "@ton/crypto",
  "@ton/sandbox",
];

export function checkCompatibility(
  dependencies: Dependencies,
  overrides: unknown
): CompatibilityResult {
  const checks: CompatibilityCheck[] = [];
  const issues: CompatibilityIssue[] = [];

  const detectedPackages = recognizedPackages.filter(
    (name) => Boolean(dependencies[name])
  );

  const hasLocklift = Boolean(dependencies.locklift);

  if (detectedPackages.length > 0) {
    checks.push({
      name: "SDK package recognition",
      status: "passed",
      message: `${detectedPackages.length} recognized ecosystem package(s) detected.`,
    });
  } else {
    checks.push({
      name: "SDK package recognition",
      status: "warning",
      message:
        "No recognized ecosystem packages were found. The project may use an unsupported SDK or a different development workflow.",
    });
  }

  // Do not claim compatibility when no verified version matrix exists.
  if (detectedPackages.length > 0) {
    const versions = detectedPackages
      .map((name) => `${name}: ${dependencies[name]}`)
      .join(", ");

    issues.push({
      severity: "info",
      category: "Version verification",
      title: "SDK version verification pending",
      message:
        `Detected packages: ${versions}. ` +
        "The scanner does not currently maintain a complete verified compatibility matrix for these versions. This is informational and does not indicate incompatibility.",
    });
  }

  // Inspect the Locklift Nekoton override without treating every
  // alternative value as a confirmed compatibility failure.
  if (hasLocklift) {
    const overrideMap =
      overrides &&
      typeof overrides === "object" &&
      !Array.isArray(overrides)
        ? (overrides as Record<string, unknown>)
        : {};

    const nekotonOverride = overrideMap["nekoton-wasm"];

    const expectedOverride =
      "npm:nekoton-wasm-locklift@^1.20.2";

    if (nekotonOverride === expectedOverride) {
      checks.push({
        name: "Locklift Nekoton override",
        status: "passed",
        message:
          "The documented Locklift Nekoton WASM override is configured.",
      });
    } else if (
      typeof nekotonOverride === "string" &&
      nekotonOverride.trim().length > 0
    ) {
      checks.push({
        name: "Locklift Nekoton override",
        status: "warning",
        message:
          `A different Nekoton override is configured: ${nekotonOverride}. Its compatibility has not been verified.`,
      });

      issues.push({
        severity: "info",
        category: "SDK compatibility",
        title: "Alternative Nekoton override detected",
        message:
          `The configured override is "${nekotonOverride}". The documented rule currently implemented by this scanner is "${expectedOverride}". Verify which override is appropriate for your installed Locklift version before changing it.`,
      });
    } else {
      checks.push({
        name: "Locklift Nekoton override",
        status: "warning",
        message:
          "The documented Locklift Nekoton WASM override was not found.",
      });

      issues.push({
        severity: "warning",
        category: "SDK compatibility",
        title: "Locklift Nekoton override not found",
        message:
          `The scanner did not find package.json overrides.nekoton-wasm. The documented rule currently implemented is "${expectedOverride}". Verify that this requirement applies to your installed Locklift version before adding it.`,
      });
    }
  }

  return { checks, issues };
}
