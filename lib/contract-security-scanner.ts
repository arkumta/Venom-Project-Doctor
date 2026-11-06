
import type { ProjectFile } from "./scanner";

export type ContractFinding = {
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

type SourceLine = {
  number: number;
  text: string;
  code: string;
};

const LIMITATIONS = [
  "ContractGuard uses heuristic static-analysis rules. It is not formal verification or a complete security audit.",
  "The current rules analyze recognizable Solidity source patterns. Venom TVM-specific behavior and compiler semantics require independent validation.",
  "Findings are indicators for manual review, not confirmed exploitable vulnerabilities.",
  "The scanner does not compile, execute, symbolically analyze, or fuzz contracts.",
  "The scanner may miss vulnerabilities that require cross-function, cross-contract, or runtime analysis.",
  "An empty findings list does not prove that a contract is secure.",
];

function maskCommentsAndStrings(source: string): string {
  let result = "";
  let state: "code" | "line" | "block" | "double" | "single" = "code";

  for (let i = 0; i < source.length; i++) {
    const char = source[i];
    const next = source[i + 1];

    if (state === "code") {
      if (char === "/" && next === "/") {
        result += "  ";
        i++;
        state = "line";
      } else if (char === "/" && next === "*") {
        result += "  ";
        i++;
        state = "block";
      } else if (char === '"') {
        result += " ";
        state = "double";
      } else if (char === "'") {
        result += " ";
        state = "single";
      } else {
        result += char;
      }
      continue;
    }

    if (state === "line") {
      if (char === "\n") {
        result += "\n";
        state = "code";
      } else {
        result += " ";
      }
      continue;
    }

    if (state === "block") {
      if (char === "*" && next === "/") {
        result += "  ";
        i++;
        state = "code";
      } else {
        result += char === "\n" ? "\n" : " ";
      }
      continue;
    }

    if (state === "double" || state === "single") {
      const closing = state === "double" ? '"' : "'";
      if (char === "\\") {
        result += "  ";
        if (i + 1 < source.length) {
          if (source[i + 1] === "\n") result += "\n";
          else result += " ";
          i++;
        }
      } else if (char === closing) {
        result += " ";
        state = "code";
      } else {
        result += char === "\n" ? "\n" : " ";
      }
    }
  }

  return result;
}

function getLines(source: string): SourceLine[] {
  const masked = maskCommentsAndStrings(source).split(/\r?\n/);
  const original = source.split(/\r?\n/);

  return original.map((text, index) => ({
    number: index + 1,
    text,
    code: masked[index] ?? "",
  }));
}

function addFinding(
  findings: ContractFinding[],
  input: Omit<ContractFinding, "id" | "manualReviewRequired">
) {
  const id = [
    input.category.toLowerCase().replace(/[^a-z0-9]+/g, "-"),
    input.file,
    input.line,
    input.title.toLowerCase().replace(/[^a-z0-9]+/g, "-"),
  ].join("-");

  if (findings.some((item) => item.id === id)) return;

  findings.push({
    ...input,
    id,
    manualReviewRequired: true,
  });
}

function getFunctionBlock(
  lines: SourceLine[],
  startIndex: number
): { endIndex: number; text: string } | null {
  let openingIndex = startIndex;

  while (
    openingIndex < lines.length &&
    !lines[openingIndex].code.includes("{")
  ) {
    if (lines[openingIndex].code.includes(";")) return null;
    openingIndex++;
  }

  if (openingIndex >= lines.length) return null;

  let depth = 0;
  let started = false;
  const collected: string[] = [];

  for (let i = openingIndex; i < lines.length; i++) {
    const code = lines[i].code;
    collected.push(code);

    for (const character of code) {
      if (character === "{") {
        depth++;
        started = true;
      } else if (character === "}") {
        depth--;
      }
    }

    if (started && depth === 0) {
      return { endIndex: i, text: collected.join("\n") };
    }
  }

  return null;
}

function scanTxOrigin(
  file: string,
  lines: SourceLine[],
  findings: ContractFinding[]
) {
  for (const line of lines) {
    if (/\btx\s*\.\s*origin\b/.test(line.code)) {
      addFinding(findings, {
        title: "tx.origin used in contract logic",
        category: "Authorization",
        severity: "high",
        confidence: "high",
        file,
        line: line.number,
        description:
          "The contract references tx.origin. If used for authorization, this can expose privileged functions to phishing-style call-chain attacks.",
        recommendation:
          "Use msg.sender or a well-reviewed access-control mechanism for authorization. Inspect every use of tx.origin and confirm it is not granting privileges.",
      });
    }
  }
}

function scanDelegateCall(
  file: string,
  lines: SourceLine[],
  findings: ContractFinding[]
) {
  for (const line of lines) {
    if (/\.delegatecall\s*\(/.test(line.code)) {
      addFinding(findings, {
        title: "Low-level delegatecall detected",
        category: "Low-level calls",
        severity: "high",
        confidence: "high",
        file,
        line: line.number,
        description:
          "delegatecall executes another address's code using the caller's storage context. An unsafe target or storage-layout mismatch can compromise contract state.",
        recommendation:
          "Verify target authorization, target immutability, storage-layout compatibility, and calldata validation. Avoid user-controlled delegatecall targets.",
      });
    }
  }
}

function scanSelfDestruct(
  file: string,
  lines: SourceLine[],
  findings: ContractFinding[]
) {
  for (const line of lines) {
    if (/\bselfdestruct\s*\(/.test(line.code)) {
      addFinding(findings, {
        title: "selfdestruct usage detected",
        category: "Contract lifecycle",
        severity: "medium",
        confidence: "high",
        file,
        line: line.number,
        description:
          "The contract uses selfdestruct. Its behavior and security implications depend on the compiler and target chain.",
        recommendation:
          "Confirm whether this operation is supported and required on the target network. Review authorization and the exact compiler semantics before deployment.",
      });
    }
  }
}

function isCallExpression(code: string): boolean {
  return (
    /\.call\s*(?:\{[^}]*\})?\s*\(/.test(code) ||
    /\.send\s*\(/.test(code)
  );
}

function getAssignedResult(code: string): string | null {
  const match = code.match(
    /\b(bool|var)\s+([A-Za-z_$][\w$]*)\s*(?:,|\s*=)/
  );
  return match?.[2] ?? null;
}

function resultIsChecked(
  lines: SourceLine[],
  callIndex: number,
  variable: string | null
): boolean {
  if (!variable) return false;

  const nearby = lines
    .slice(callIndex, Math.min(callIndex + 9, lines.length))
    .map((line) => line.code)
    .join("\n");

  const escaped = variable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  return (
    new RegExp(`\\brequire\\s*\\(\\s*${escaped}\\b`).test(nearby) ||
    new RegExp(`\\bassert\\s*\\(\\s*${escaped}\\b`).test(nearby) ||
    new RegExp(`\\bif\\s*\\(\\s*!\\s*${escaped}\\b`).test(nearby) ||
    new RegExp(`\\bif\\s*\\(\\s*${escaped}\\b`).test(nearby)
  );
}

function scanExternalCalls(
  file: string,
  lines: SourceLine[],
  findings: ContractFinding[]
) {
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    if (!isCallExpression(line.code)) continue;

    const variable = getAssignedResult(line.code);
    const checked = resultIsChecked(lines, index, variable);

    if (checked) continue;

    addFinding(findings, {
      title: variable
        ? "Low-level call result may be unchecked"
        : "Low-level call return value is not captured",
      category: "External calls",
      severity: "high",
      confidence: "medium",
      file,
      line: line.number,
      description: variable
        ? `The call result is assigned to "${variable}", but no obvious require, assert, or conditional check was found nearby.`
        : "A low-level call or send expression appears without capturing its return value. Failure may not be handled explicitly.",
      recommendation:
        "Capture the returned success value and handle failure explicitly. Confirm that the call target and transferred value are expected and that external control transfer is safe.",
    });
  }
}

function scanPossibleReentrancy(
  file: string,
  lines: SourceLine[],
  findings: ContractFinding[]
) {
  const stateNames =
    /\b(balance|balances|owner|totalSupply|withdrawn|claimed|pending|credits|accounted|shares|deposits|userBalance)\b/;

  for (let index = 0; index < lines.length; index++) {
    if (!/\bfunction\s+[A-Za-z_$][\w$]*/.test(lines[index].code)) {
      continue;
    }

    const block = getFunctionBlock(lines, index);
    if (!block) continue;

    const body = lines.slice(index, block.endIndex + 1);
    const callIndex = body.findIndex((line) =>
      /\.(?:call|transfer|send)\s*(?:\{[^}]*\})?\s*\(/.test(line.code)
    );

    if (callIndex === -1) {
      index = block.endIndex;
      continue;
    }

    const stateWriteAfterCall = body
      .slice(callIndex + 1)
      .some((line) =>
        new RegExp(
          `\\b${stateNames.source}\\b\\s*(?:\\[[^\\]]+\\])?\\s*(?:=|\\+=|-=|\\+\\+|--)`
        ).test(line.code)
      );

    if (stateWriteAfterCall) {
      addFinding(findings, {
        title: "Possible reentrancy pattern",
        category: "Reentrancy",
        severity: "high",
        confidence: "medium",
        file,
        line: body[callIndex].number,
        description:
          "An external call appears before a later write to a state-like variable in the same function. This ordering may expose a reentrancy risk.",
        recommendation:
          "Review all reachable call paths. Apply checks-effects-interactions ordering, update state before external calls where appropriate, and consider a suitable reentrancy guard.",
      });
    }

    index = block.endIndex;
  }
}

function scanUncheckedBlocks(
  file: string,
  lines: SourceLine[],
  findings: ContractFinding[]
) {
  for (const line of lines) {
    if (/\bunchecked\s*\{/.test(line.code)) {
      addFinding(findings, {
        title: "Unchecked arithmetic block detected",
        category: "Arithmetic",
        severity: "medium",
        confidence: "high",
        file,
        line: line.number,
        description:
          "An unchecked block disables Solidity's automatic arithmetic overflow and underflow checks for operations inside the block.",
        recommendation:
          "Review every arithmetic operation in the block. Add explicit bounds checks or prove that the operands cannot overflow or underflow.",
      });
    }
  }
}

function summarize(findings: ContractFinding[]) {
  return {
    total: findings.length,
    critical: findings.filter((item) => item.severity === "critical").length,
    high: findings.filter((item) => item.severity === "high").length,
    medium: findings.filter((item) => item.severity === "medium").length,
    low: findings.filter((item) => item.severity === "low").length,
    info: findings.filter((item) => item.severity === "info").length,
  };
}

export function scanContractSecurity(
  files: ProjectFile[]
): ContractSecurityReport {
  const solidityFiles = files.filter((file) => /\.sol$/i.test(file.path));
  const findings: ContractFinding[] = [];

  for (const file of solidityFiles) {
    const lines = getLines(file.content);

    scanTxOrigin(file.path, lines, findings);
    scanDelegateCall(file.path, lines, findings);
    scanSelfDestruct(file.path, lines, findings);
    scanExternalCalls(file.path, lines, findings);
    scanPossibleReentrancy(file.path, lines, findings);
    scanUncheckedBlocks(file.path, lines, findings);
  }

  const severityOrder = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };

  findings.sort(
    (a, b) =>
      severityOrder[a.severity] - severityOrder[b.severity] ||
      a.file.localeCompare(b.file) ||
      a.line - b.line
  );

  return {
    status: solidityFiles.length > 0 ? "completed" : "skipped",
    message:
      solidityFiles.length > 0
        ? "Solidity source files were checked using preliminary static-analysis rules."
        : "No Solidity (.sol) source files were found. Contract security scanning was skipped.",
    summary: {
      filesScanned: solidityFiles.length,
      ...summarize(findings),
    },
    findings,
    scannedAt: new Date().toISOString(),
    limitations: LIMITATIONS,
  };
}
