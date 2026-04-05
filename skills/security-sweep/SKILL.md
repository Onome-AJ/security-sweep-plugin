---
name: security-sweep
description: Scan codebase for security vulnerabilities, hardcoded secrets, injection flaws, misconfigurations, and attack surfaces. Use when user wants a security audit, vulnerability scan, or to find security issues.
argument-hint: "[scope: all|secrets|injection|auth|config|deps|ai|mobile|data] [path]"
allowed-tools: Read, Grep, Glob, Bash, Agent
effort: max
---

# Security Sweep

Run a comprehensive security scan of the codebase. This skill identifies vulnerabilities, hardcoded secrets, injection flaws, misconfigurations, and attack surfaces across web and mobile applications.

## Arguments

- `$0` (optional): Scan scope — one of: `all`, `secrets`, `injection`, `auth`, `config`, `deps`, `ai`, `mobile`, `data`. Defaults to `all`.
- `$1` (optional): Path to scan. Defaults to the project root.

If `$ARGUMENTS` is empty, run a full `all` scan from the project root.

## Execution Plan

### Step 1: Tech Stack Detection

Before scanning, detect the project's tech stack by checking for indicator files. This determines which language-specific checks to run.

| Indicator File | Stack | Scan Focus |
|---|---|---|
| `package.json` | Node.js/JS/TS | npm patterns, XSS sinks, eval, child_process |
| `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile` | Python | pickle, subprocess, Jinja2, Django/Flask patterns |
| `pom.xml`, `build.gradle`, `build.gradle.kts` | Java/Kotlin | JDBC injection, ObjectInputStream, Spring patterns |
| `Gemfile` | Ruby | Marshal, system(), ERB patterns |
| `go.mod` | Go | fmt.Sprintf in SQL, crypto patterns |
| `Cargo.toml` | Rust | unsafe blocks, FFI |
| `composer.json` | PHP | exec, unserialize, include with vars |
| `*.csproj` | .NET | BinaryFormatter, SqlCommand concat |
| `AndroidManifest.xml` | Android | exported components, cleartext, SharedPreferences |
| `Info.plist`, `*.xcodeproj`, `Podfile` | iOS | NSUserDefaults, ATS bypass |
| `Dockerfile` | Docker | FROM :latest, root user, secrets in build |
| `*.tf`, `*.hcl` | Terraform | public ACLs, open CIDR |
| `next.config.*` | Next.js | SSR-specific checks |
| `pubspec.yaml` | Flutter/Dart | Dart-specific mobile checks |

Use `Glob` to detect which of these exist, then tailor the scan accordingly.

### Step 2: Run Scans by Priority

Run the scans below in order. If a scope argument was provided, only run that specific scan module. Use the patterns from [patterns.md](patterns.md) for each module.

**For each scan module**, use `Grep` with the relevant regex patterns from [patterns.md](patterns.md). Search across the detected file types. Skip `node_modules/`, `vendor/`, `.git/`, `dist/`, `build/`, `__pycache__/`, `.venv/`, `venv/`, `.next/`, `.nuxt/`, `target/`, `Pods/`, `.gradle/` directories.

#### Module 1: SECRETS (Critical Priority)
Scan for hardcoded API keys, tokens, private keys, credentials, database connection strings, and committed secret files. See [patterns.md](patterns.md) Section 1.

Also check:
- Whether `.env` files exist in the repo (they should be gitignored)
- Whether `.gitignore` covers `.env*`, `*.pem`, `*.key`, `*.p12`, `credentials*.json`
- Whether any `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks` files are present

#### Module 2: INJECTION (Critical Priority)
Scan for SQL injection, XSS, command injection, SSRF, insecure deserialization, and path traversal patterns. See [patterns.md](patterns.md) Section 2.

#### Module 3: AUTH (High Priority)
Scan for JWT misuse, weak password handling, insecure session config, broken access control. See [patterns.md](patterns.md) Section 3.

#### Module 4: CONFIG (High Priority)
Scan for CORS misconfiguration, missing security headers, exposed debug endpoints, insecure TLS, Docker issues, Kubernetes/Terraform misconfig. See [patterns.md](patterns.md) Section 4.

#### Module 5: DEPS (High Priority)
Check dependency manifests for:
- Missing lockfiles alongside manifests
- Suspicious install scripts in package.json (`preinstall`/`postinstall` with curl/wget/bash)
- Known risky or deprecated packages

#### Module 6: AI (High Priority)
Scan for AI-specific issues: hardcoded AI API keys, prompt injection vectors, eval/exec of LLM output, system prompt leakage, excessive agent permissions. See [patterns.md](patterns.md) Section 5.

#### Module 7: MOBILE (High Priority — only if Android/iOS detected)
Scan for insecure data storage, missing certificate pinning, cleartext traffic, debug flags, weak crypto. See [patterns.md](patterns.md) Section 6.

#### Module 8: DATA (Medium Priority)
Scan for PII in logs, sensitive data in URLs, plaintext HTTP to external hosts. See [patterns.md](patterns.md) Section 7.

### Step 3: Generate Report

After all scans complete, produce a structured report.

#### Report Format

Start with a summary banner:

```
============================================
  SECURITY SWEEP REPORT
  Project: <project name>
  Scanned: <date>
  Tech Stack: <detected stacks>
============================================

SUMMARY
  CRITICAL: <count>
  HIGH:     <count>
  MEDIUM:   <count>
  LOW:      <count>
  INFO:     <count>
  TOTAL:    <count>
============================================
```

Then list findings grouped by severity (CRITICAL first), with this format for each:

```
[SEVERITY] CATEGORY — Finding Title
  File: path/to/file.ext:line_number
  Evidence: <the matching code snippet, max 2 lines>
  Risk: <1-sentence explanation of the attack scenario>
  Fix: <specific remediation with code example>
  Ref: <CWE or OWASP reference>
```

#### After the findings, include:

1. **Top 3 Priorities** — The 3 most impactful issues to fix first, with reasoning
2. **Positive Findings** — Security practices the project is doing well (e.g., using parameterized queries, proper .gitignore, CSP headers present)
3. **Recommendations** — General security improvements not tied to a specific finding

### Important Guidelines

- **Minimize false positives**: When a pattern match looks like it might be a false positive (e.g., a test file, a comment, an example/documentation), note it as `[INFO]` rather than flagging it at high severity. Use your contextual understanding of the code to distinguish real issues from benign matches.
- **Read files for context**: When a grep match is ambiguous, use `Read` to examine surrounding code before classifying severity. For example, a `pickle.load()` in a test fixture is lower risk than one in a web endpoint.
- **Skip vendored/generated code**: Do not flag issues in `node_modules/`, `vendor/`, generated files, or lock files.
- **Be framework-aware**: Understand that some frameworks have built-in protections (e.g., Django ORM prevents SQL injection, React escapes by default, Angular sanitizes innerHTML). Adjust severity accordingly.
- **Deduplicate**: If the same pattern appears many times (e.g., `console.log(req.body)` in 20 files), group them as one finding with a count rather than listing each separately.
