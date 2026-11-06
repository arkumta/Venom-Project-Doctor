
"use client";

import { useState } from "react";
import {
  ShieldCheck,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Info,
  FileCode2,
} from "lucide-react";

type ContractFinding = {
  id: string;
  title: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: "high" | "medium" | "low";
  file: string;
  line: number;
  description: string;
  recommendation: string;
  manualReviewRequired: boolean;
};

export type ContractSecurityReport = {
  status: "completed" | "skipped";
  message: string;
  summary: {
    filesScanned: number;
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings: ContractFinding[];
  scannedAt: string;
  limitations: string[];
};

type Props = {
  report: ContractSecurityReport | null;
};

const severityStyles: Record<string, string> = {
  critical: "border-red-500/20 bg-red-500/10 text-red-400",
  high: "border-orange-500/20 bg-orange-500/10 text-orange-400",
  medium: "border-amber-500/20 bg-amber-500/10 text-amber-300",
  low: "border-blue-500/20 bg-blue-500/10 text-blue-300",
  info: "border-white/10 bg-white/5 text-[#aab5ad]",
};

export default function ContractGuardPanel({ report }: Props) {
  const [expanded, setExpanded] = useState<string[]>([]);

  const toggleFinding = (id: string) => {
    setExpanded((current) =>
      current.includes(id)
        ? current.filter((item) => item !== id)
        : [...current, id]
    );
  };

  return (
    <section className="rounded-xl border border-[#b8f36b]/20 bg-[#101711] p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-[#b8f36b]/10 p-2 text-[#b8f36b]">
            <ShieldCheck size={21} />
          </div>
          <div>
            <h3 className="text-lg font-semibold">ContractGuard</h3>
            <p className="mt-1 text-xs text-[#87938a]">
              Preliminary smart contract source-code analysis
            </p>
          </div>
        </div>

        {report && (
          <span
            className={`rounded-full px-3 py-1 text-xs ${
              report.status === "completed"
                ? "bg-[#b8f36b]/10 text-[#b8f36b]"
                : "bg-amber-500/10 text-amber-300"
            }`}
          >
            {report.status.toUpperCase()}
          </span>
        )}
      </div>

      {!report ? (
        <p className="mt-5 text-sm text-amber-300">
          Contract security report was not returned by the server.
        </p>
      ) : (
        <>
          <p className="mt-4 text-sm text-[#aab5ad]">{report.message}</p>

          {report.status === "completed" && (
            <>
              <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
                {[
                  { label: "Files scanned", value: report.summary.filesScanned },
                  { label: "Total findings", value: report.summary.total },
                  { label: "Critical", value: report.summary.critical },
                  { label: "High", value: report.summary.high },
                  { label: "Medium", value: report.summary.medium },
                  { label: "Low / Info", value: report.summary.low + report.summary.info },
                ].map((item) => (
                  <div
                    key={item.label}
                    className="rounded-lg border border-white/10 bg-black/20 p-3"
                  >
                    <div className="text-2xl font-bold text-[#b8f36b]">
                      {item.value}
                    </div>
                    <div className="mt-1 text-xs text-[#87938a]">
                      {item.label}
                    </div>
                  </div>
                ))}
              </div>

              {report.findings.length === 0 ? (
                <div className="mt-5 rounded-lg border border-[#b8f36b]/20 bg-[#b8f36b]/5 p-4">
                  <div className="flex items-center gap-2 text-sm font-semibold text-[#b8f36b]">
                    <ShieldCheck size={17} />
                    No findings from the current rules
                  </div>
                  <p className="mt-2 text-xs leading-5 text-[#aab5ad]">
                    This does not prove that the contracts are secure. The
                    current scanner checks only a limited set of source patterns.
                  </p>
                </div>
              ) : (
                <div className="mt-6 space-y-3">
                  {report.findings.map((finding) => {
                    const isExpanded = expanded.includes(finding.id);

                    return (
                      <div
                        key={finding.id}
                        className="overflow-hidden rounded-lg border border-white/10 bg-black/20"
                      >
                        <button
                          type="button"
                          onClick={() => toggleFinding(finding.id)}
                          className="flex w-full flex-wrap items-center justify-between gap-3 p-4 text-left"
                        >
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <span
                                className={`rounded border px-2 py-1 text-[10px] font-bold uppercase ${
                                  severityStyles[finding.severity]
                                }`}
                              >
                                {finding.severity}
                              </span>
                              <span className="text-[10px] text-[#87938a]">
                                {finding.category}
                              </span>
                            </div>

                            <h4 className="mt-2 text-sm font-semibold text-[#e8eee9]">
                              {finding.title}
                            </h4>

                            <p className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-[#b8f36b]">
                              <FileCode2 size={13} />
                              <span className="break-all">{finding.file}</span>
                              <span className="text-[#87938a]">
                                Line {finding.line}
                              </span>
                            </p>
                          </div>

                          {isExpanded ? (
                            <ChevronUp size={18} className="shrink-0 text-[#87938a]" />
                          ) : (
                            <ChevronDown size={18} className="shrink-0 text-[#87938a]" />
                          )}
                        </button>

                        {isExpanded && (
                          <div className="border-t border-white/[0.07] p-4">
                            <div className="flex flex-wrap gap-2 text-[10px]">
                              <span className="rounded bg-white/5 px-2 py-1 text-[#aab5ad]">
                                Confidence: {finding.confidence}
                              </span>
                              <span className="rounded bg-white/5 px-2 py-1 text-[#aab5ad]">
                                Line: {finding.line}
                              </span>
                              {finding.manualReviewRequired && (
                                <span className="rounded bg-amber-500/10 px-2 py-1 text-amber-300">
                                  Manual review required
                                </span>
                              )}
                            </div>

                            <div className="mt-4">
                              <p className="text-xs font-semibold text-[#e8eee9]">
                                Explanation
                              </p>
                              <p className="mt-2 text-xs leading-5 text-[#aab5ad]">
                                {finding.description}
                              </p>
                            </div>

                            <div className="mt-4 rounded-lg border border-[#b8f36b]/10 bg-[#b8f36b]/5 p-3">
                              <p className="text-xs font-semibold text-[#b8f36b]">
                                Recommended action
                              </p>
                              <p className="mt-2 text-xs leading-5 text-[#c2ccc4]">
                                {finding.recommendation}
                              </p>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </>
          )}

          <div className="mt-5 rounded-lg border border-amber-500/15 bg-amber-500/[0.04] p-4">
            <div className="flex items-center gap-2 text-xs font-semibold text-amber-300">
              <AlertTriangle size={15} />
              Important limitations
            </div>
            <ul className="mt-2 list-disc space-y-1 pl-5 text-[11px] leading-5 text-[#aab5ad]">
              {report.limitations.map((limitation, index) => (
                <li key={index}>{limitation}</li>
              ))}
            </ul>
            <p className="mt-3 flex items-start gap-2 text-[11px] leading-5 text-[#87938a]">
              <Info size={14} className="mt-0.5 shrink-0" />
              Findings are preliminary indicators, not confirmed
              vulnerabilities or a substitute for a professional security audit.
            </p>
          </div>
        </>
      )}
    </section>
  );
}
