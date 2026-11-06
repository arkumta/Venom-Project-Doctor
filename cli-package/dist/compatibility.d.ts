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
export declare function checkCompatibility(dependencies: Dependencies, overrides: unknown): CompatibilityResult;
export {};
