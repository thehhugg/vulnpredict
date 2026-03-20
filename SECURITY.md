# Security Policy

## Supported Versions

The following versions of VulnPredict are currently supported with security updates:

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

As VulnPredict is a security tool, we take vulnerabilities in our own codebase extremely seriously. We aim to maintain the highest standards of security hygiene.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Instead, please use one of the following methods:

### Preferred: GitHub Security Advisories

1. Navigate to the [Security Advisories](https://github.com/thehhugg/vulnpredict/security/advisories) page for this repository.
2. Click **"Report a vulnerability"** to open a private advisory draft.
3. Provide as much detail as possible (see below).

This method ensures the report remains confidential and allows us to collaborate on a fix before public disclosure.

### Alternative: Email

If you are unable to use GitHub Security Advisories, you may send an email to the repository maintainer. Please include **[SECURITY]** in the subject line.

## Scope

The following are **in scope** for vulnerability reports:

- The VulnPredict Python package and all its modules (analyzers, ML pipeline, CLI, data ingestion).
- The CI/CD pipeline and build infrastructure.
- Dependencies shipped with or required by VulnPredict.

The following are **out of scope**:

- Vulnerabilities in third-party services (e.g., NVD API, OSV.dev) that VulnPredict integrates with.
- Issues in the demo project files, which are intentionally vulnerable for testing purposes.
- Social engineering attacks against maintainers or contributors.

## What to Include in Your Report

To help us triage and respond quickly, please include:

- **Description** of the vulnerability and its potential impact.
- **Affected version(s)** of VulnPredict.
- **Steps to reproduce** the issue, including any proof-of-concept code or commands.
- **Environment details** (OS, Python version, installation method).
- **Suggested fix** (if you have one).

## Response Timeline

We are committed to the following response timeline:

| Stage | Timeline |
|-------|----------|
| **Acknowledgment** | Within 48 hours of receiving the report |
| **Initial assessment** | Within 5 business days |
| **Fix for critical vulnerabilities** | Within 14 days |
| **Fix for high-severity vulnerabilities** | Within 30 days |
| **Fix for medium/low-severity vulnerabilities** | Within 60 days |

If we are unable to meet these timelines, we will communicate the delay and provide an updated estimate.

## Coordinated Disclosure Process

We follow a coordinated disclosure process:

1. **Report received.** We acknowledge receipt within 48 hours and begin our assessment.
2. **Triage and investigation.** We verify the vulnerability, determine its severity using CVSS v3.1, and identify affected versions.
3. **Fix development.** We develop and test a fix in a private branch.
4. **Pre-disclosure notification.** If the vulnerability affects downstream users, we may notify key stakeholders before public disclosure.
5. **Release and advisory.** We release the patched version and publish a GitHub Security Advisory with full details, including CVE assignment if applicable.
6. **Public disclosure.** The vulnerability details are made public through the advisory. We request that reporters wait until this stage before any public disclosure.

## Severity Classification

We use the [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) framework to assess vulnerability severity:

| CVSS Score | Severity | Response Priority |
|------------|----------|-------------------|
| 9.0 - 10.0 | Critical | Immediate (within 14 days) |
| 7.0 - 8.9 | High | High (within 30 days) |
| 4.0 - 6.9 | Medium | Standard (within 60 days) |
| 0.1 - 3.9 | Low | Scheduled (next release) |

## Security Best Practices for Contributors

If you are contributing to VulnPredict, please follow these practices:

- **Never commit secrets, API keys, or credentials.** The `detect-secrets` pre-commit hook will help prevent this.
- **Run `bandit`** on your changes before submitting a PR. This is enforced by the pre-commit hooks.
- **Keep dependencies up to date.** Report any known vulnerable dependencies you discover.
- **Follow the principle of least privilege** when writing code that interacts with the filesystem, network, or subprocess calls.

## Recognition

We appreciate the efforts of security researchers who help keep VulnPredict and its users safe. With the reporter's permission, we will acknowledge their contribution in the security advisory and in our release notes.

## Encrypted Communication

We do not currently have a PGP key for encrypted email communication. If you require encrypted communication, please use [GitHub Security Advisories](https://github.com/thehhugg/vulnpredict/security/advisories), which provide end-to-end confidentiality by default.

## Contact

For security-related questions that are not vulnerability reports, please open a regular [GitHub Issue](https://github.com/thehhugg/vulnpredict/issues).
