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
export declare function scanSecurity(projectRoot: string): Promise<SecurityAuditReport>;
