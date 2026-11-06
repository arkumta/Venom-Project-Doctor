
import { NextRequest, NextResponse } from "next/server";
import {
  scanProject,
  type ProjectFile,
} from "@/lib/scanner";
import { scanSecurity } from "@/lib/security-scanner";
import { scanContractSecurity } from "@/lib/contract-security-scanner";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    if (
      !body ||
      !Array.isArray(body.files) ||
      body.files.length === 0 ||
      body.files.length > 500
    ) {
      return NextResponse.json(
        {
          success: false,
          error: "Invalid project files. Maximum: 500 files.",
        },
        { status: 400 }
      );
    }

    const files: ProjectFile[] = [];
    let totalSize = 0;

    for (const file of body.files) {
      if (
        !file ||
        typeof file.path !== "string" ||
        typeof file.content !== "string"
      ) {
        return NextResponse.json(
          {
            success: false,
            error: "Each file must contain a valid path and text content.",
          },
          { status: 400 }
        );
      }

      const path = file.path.replace(/\\/g, "/");
      const parts = path.split("/");

      if (
        path.startsWith("/") ||
        parts.some((part: string) => part === "." || part === "..") ||
        /^[a-zA-Z]:/.test(path)
      ) {
        return NextResponse.json(
          {
            success: false,
            error: "Invalid project file path detected.",
          },
          { status: 400 }
        );
      }

      totalSize += new TextEncoder().encode(file.content).length;

      if (totalSize > 5 * 1024 * 1024) {
        return NextResponse.json(
          {
            success: false,
            error: "Project files exceed the 5 MB scanning limit.",
          },
          { status: 400 }
        );
      }

      files.push({
        path,
        content: file.content,
      });
    }

    const report = scanProject(files);
    const securityReport = await scanSecurity(files);
    const contractSecurityReport = scanContractSecurity(files);

    return NextResponse.json({
      success: true,
      report,
      securityReport,
      contractSecurityReport,
    });
  } catch {
    return NextResponse.json(
      {
        success: false,
        error: "Unable to scan project. Check the submitted JSON.",
      },
      { status: 400 }
    );
  }
}
