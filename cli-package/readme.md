
# Venom Doctor

CLI diagnostics for Venom and Locklift smart contract projects.

Venom Doctor scans your project and reports detected tools, configuration checks, and potential compatibility issues.

## Installation

```bash
npm install -g venom-doctor
```

## Usage

Scan the current project:

```bash
venom-doctor scan
```

Scan a specific project:

```bash
venom-doctor scan ../my-project
```

Output JSON:

```bash
venom-doctor scan ../my-project --json
```

## What it checks

- Project package.json
- Recognized Venom and Locklift dependencies
- Locklift configuration
- Nekoton WASM override
- Solidity and smart contract source files
- Compiler configuration
- Environment configuration

## Important

Venom Doctor provides preliminary project diagnostics. A passing result does not guarantee that a project builds successfully, is secure, or is fully compatible.

## License

MIT
