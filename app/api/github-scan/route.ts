
import { NextRequest, NextResponse } from "next/server";
import { scanProject, type ProjectFile } from "@/lib/scanner";
import { scanSecurity } from "@/lib/security-scanner";
import { scanContractSecurity } from "@/lib/contract-security-scanner";

const MAX_FILES = 800;
const MAX_TOTAL_BYTES = 5 * 1024 * 1024;
const MAX_FILE_BYTES = 1024 * 1024;

const IGNORED_DIRECTORIES = new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  "coverage",
  ".turbo",
  ".vercel",
]);

type GitHubRepository = {
  default_branch: string;
  full_name: string;
  private: boolean;
};

type GitHubTreeItem = {
  path: string;
  type: string;
  size?: number;
  sha: string;
};

type GitHubTree = {
  tree: GitHubTreeItem[];
  truncated: boolean;
};

function isSupportedFile(path: string): boolean {
  const parts = path.split("/");
  const filename = parts[parts.length - 1];

  if (parts.some((part) => IGNORED_DIRECTORIES.has(part))) return false;

  if (
    filename.startsWith(".env") ||
    [".npmrc", ".pypirc", "id_rsa", "id_ed25519"].includes(filename)
  ) {
    return false;
  }

  return (
    filename === "package.json" ||
    filename === "package-lock.json" ||
    /^locklift\.config\.(ts|js|cjs|mjs)$/.test(filename) ||
    /\.(sol|t\.sol|leo|json|ts|js|cjs|mjs)$/.test(filename)
  );
}

function parseRepositoryUrl(value: unknown) {
  if (typeof value !== "string" || value.length > 500) {
    throw new Error("Enter a valid public GitHub repository URL.");
  }

  let url: URL;

  try {
    url = new URL(value.trim());
  } catch {
    throw new Error("The GitHub repository URL is invalid.");
  }

  if (
    url.protocol !== "https:" ||
    url.hostname !== "github.com" ||
    url.username ||
    url.password
  ) {
    throw new Error("Only HTTPS URLs from github.com are supported.");
  }

  const parts = url.pathname.split("/").filter(Boolean);

  if (
    parts.length !== 2 ||
    parts.some((part) => part === "." || part === "..") ||
    parts[1].endsWith(".git")
  ) {
    throw new Error(
      "Enter a repository URL in this format: https://github.com/owner/repository"
    );
  }

  const [owner, repo] = parts;

  if (
    !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(owner) ||
    !/^[A-Za-z0-9_.-]{1,100}$/.test(repo)
  ) {
    throw new Error("The repository owner or name is invalid.");
  }

  return { owner, repo };
}

function githubHeaders(): HeadersInit {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "Venom-Project-Doctor",
  };

  // Optional token for higher GitHub API rate limits.
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }

  return headers;
}

async function fetchGitHubJson<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    headers: githubHeaders(),
    cache: "no-store",
  });

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error(
        "Repository not found or not publicly accessible. Check the URL."
      );
    }

    if (response.status === 403 || response.status === 429) {
      throw new Error(
        "GitHub API rate limit reached. Please wait before trying again."
      );
    }

    throw new Error(`GitHub returned an error (${response.status}).`);
  }

  return (await response.json()) as T;
}

async function fetchSourceFile(
  owner: string,
  repo: string,
  branch: string,
  path: string
): Promise<ProjectFile> {
  const encodedBranch = encodeURIComponent(branch).replace(/%2F/gi, "/");
  const encodedPath = path
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");

  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${encodedBranch}/${encodedPath}`;

  const response = await fetch(url, {
    cache: "no-store",
    headers: { "User-Agent": "Venom-Project-Doctor" },
  });

  if (!response.ok) {
    throw new Error(`Unable to download repository file: ${path}`);
  }

  const contentLength = Number(response.headers.get("content-length") || 0);

  if (contentLength > MAX_FILE_BYTES) {
    throw new Error(`File exceeds the 1 MB limit: ${path}`);
  }

  const buffer = await response.arrayBuffer();

  if (buffer.byteLength > MAX_FILE_BYTES) {
    throw new Error(`File exceeds the 1 MB limit: ${path}`);
  }

  return {
    path,
    content: new TextDecoder("utf-8", { fatal: false }).decode(buffer),
  };
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { owner, repo } = parseRepositoryUrl(body?.repositoryUrl);

    const repository = await fetchGitHubJson<GitHubRepository>(
      `https://api.github.com/repos/${owner}/${repo}`
    );

    if (repository.private) {
      return NextResponse.json(
        {
          success: false,
          error: "Private repositories are not supported yet.",
        },
        { status: 400 }
      );
    }

    const tree = await fetchGitHubJson<GitHubTree>(
      `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(
        repository.default_branch
      )}?recursive=1`
    );

    if (tree.truncated) {
      return NextResponse.json(
        {
          success: false,
          error:
            "This repository is too large for the initial GitHub scanner. Try a smaller repository.",
        },
        { status: 400 }
      );
    }

    const supportedFiles = tree.tree.filter(
      (item) =>
        item.type === "blob" &&
        isSupportedFile(item.path)
    );

    if (supportedFiles.length === 0) {
      return NextResponse.json(
        {
          success: false,
          error:
            "No supported source or configuration files were found in this repository.",
        },
        { status: 400 }
      );
    }

    if (supportedFiles.length > MAX_FILES) {
      return NextResponse.json(
        {
          success: false,
          error: `Repository contains ${supportedFiles.length} supported files. Maximum: ${MAX_FILES}.`,
        },
        { status: 400 }
      );
    }

    const declaredBytes = supportedFiles.reduce(
      (total, item) => total + (item.size ?? 0),
      0
    );

    if (declaredBytes > MAX_TOTAL_BYTES) {
      return NextResponse.json(
        {
          success: false,
          error: "Repository source files exceed the 5 MB scanning limit.",
        },
        { status: 400 }
      );
    }

    const files: ProjectFile[] = [];

    // Download files in small batches to avoid overwhelming GitHub.
    for (let i = 0; i < supportedFiles.length; i += 8) {
      const batch = supportedFiles.slice(i, i + 8);

      const downloaded = await Promise.all(
        batch.map((item) =>
          fetchSourceFile(
            owner,
            repo,
            repository.default_branch,
            item.path
          )
        )
      );

      files.push(...downloaded);

      const actualBytes = files.reduce(
        (total, file) =>
          total + new TextEncoder().encode(file.content).byteLength,
        0
      );

      if (actualBytes > MAX_TOTAL_BYTES) {
        throw new Error(
          "Downloaded repository files exceed the 5 MB scanning limit."
        );
      }
    }

    const report = scanProject(files);
    const securityReport = await scanSecurity(files);
    const contractSecurityReport = scanContractSecurity(files);

    return NextResponse.json({
      success: true,
      repository: {
        name: repository.full_name,
        url: `https://github.com/${owner}/${repo}`,
        branch: repository.default_branch,
        filesScanned: files.length,
      },
      report,
      securityReport,
      contractSecurityReport,
    });
  } catch (error) {
    return NextResponse.json(
      {
        success: false,
        error:
          error instanceof Error
            ? error.message
            : "Unable to scan the GitHub repository.",
      },
      { status: 400 }
    );
  }
}
