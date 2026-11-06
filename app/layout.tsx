
import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Venom Project Doctor | Developer Diagnostics",
  description:
    "Scan Venom blockchain projects for SDK compatibility, outdated dependencies, deprecated APIs and configuration issues.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
