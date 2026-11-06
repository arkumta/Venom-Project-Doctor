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
    tools: {
        name: string;
        version: string;
    }[];
    checks: {
        name: string;
        status: "passed" | "warning" | "failed";
        message: string;
    }[];
    issues: ScanIssue[];
    scannedAt: string;
};
export declare function scanProject(files: ProjectFile[]): ScanReport;
