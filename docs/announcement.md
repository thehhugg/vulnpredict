# VulnPredict Launch Announcement

## Blog Post Draft

### VulnPredict: ML-Powered Vulnerability Detection for Your Codebase

**TL;DR:** VulnPredict is an open-source static analysis tool that combines
traditional pattern matching with machine learning to detect security
vulnerabilities in Python, JavaScript, TypeScript, Go, and Infrastructure
as Code (Terraform, Dockerfile, Kubernetes).

---

#### The Problem

Modern applications are built with multiple languages, frameworks, and
infrastructure definitions. Existing security tools often focus on a single
language or rely solely on pattern matching, missing subtle vulnerabilities
that require deeper analysis.

#### What VulnPredict Does

VulnPredict provides a unified scanning experience across your entire stack:

- **Python** — SQL injection, command injection, XSS, deserialization,
  SSRF, weak crypto, path traversal, and more
- **JavaScript/TypeScript** — Prototype pollution, ReDoS, DOM XSS,
  insecure randomness, type assertion bypasses
- **Go** — SQL injection, command injection, path traversal, weak crypto
- **Infrastructure as Code** — Terraform misconfigurations, Dockerfile
  security issues, Kubernetes privilege escalation

#### Key Features

| Feature | Description |
|---------|-------------|
| ML-powered scoring | CodeBERT embeddings for semantic code understanding |
| Configurable rules | YAML-based custom rule engine |
| Scan profiles | Quick, standard, and deep analysis modes |
| Multiple outputs | JSON, SARIF, HTML, Markdown formats |
| Secrets detection | 15+ patterns for API keys, tokens, credentials |
| Baseline comparison | Track new vs. existing findings across scans |
| CI integration | GitHub Actions, pre-commit hooks, exit codes |
| Dashboard API | FastAPI-based REST API for scan result management |

#### Getting Started

```bash
pip install vulnpredict
vulnpredict scan /path/to/project --format json
```

#### Links

- **GitHub:** https://github.com/thehhugg/vulnpredict
- **Documentation:** See the `docs/` directory
- **License:** MIT

---

## Directory Submission Checklist

| Target | URL | Status |
|--------|-----|--------|
| awesome-security | https://github.com/sbilly/awesome-security | Pending |
| awesome-static-analysis | https://github.com/analysis-tools-dev/static-analysis | Pending |
| awesome-python-security | https://github.com/guardrailsio/awesome-python-security | Pending |
| Hacker News (Show HN) | https://news.ycombinator.com/submit | Pending |
| Reddit r/netsec | https://reddit.com/r/netsec | Pending |
| Reddit r/Python | https://reddit.com/r/Python | Pending |
| Dev.to | https://dev.to | Pending |
| OWASP Community Tools | https://owasp.org/www-community/ | Pending |

## Show HN Post Template

**Title:** Show HN: VulnPredict — ML-powered vulnerability scanner for Python, JS, Go, and IaC

**Text:**

Hi HN, I built VulnPredict, an open-source security scanner that combines
static analysis with machine learning to detect vulnerabilities across
Python, JavaScript/TypeScript, Go, and Infrastructure as Code.

Key differentiators:
- CodeBERT embeddings for semantic understanding beyond pattern matching
- YAML-based custom rules so teams can encode their own security policies
- Unified scanning across languages and IaC (Terraform, Dockerfile, K8s)
- Multiple output formats including SARIF for IDE integration

It's MIT licensed and available at: https://github.com/thehhugg/vulnpredict

Would love feedback on the detection accuracy and any false positive/negative
experiences you encounter.

## Reddit Post Template

**Title:** VulnPredict: Open-source ML-powered vulnerability scanner for Python, JS, Go, and IaC

**Body:** (Same as Show HN text above, adapted for the subreddit audience)
