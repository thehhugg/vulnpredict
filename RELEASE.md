# Release Process

This document describes how to create a new release of VulnPredict.

## Overview

VulnPredict follows [Semantic Versioning](https://semver.org/). Releases are automated through GitHub Actions and published to PyPI using trusted publishing (OIDC).

| Version Component | When to Bump | Example |
|-------------------|-------------|---------|
| **MAJOR** (X.0.0) | Breaking API or CLI changes | Removing a CLI flag, changing output schema |
| **MINOR** (0.X.0) | New features, new analyzers, new output formats | Adding Go analyzer, adding HTML reports |
| **PATCH** (0.0.X) | Bug fixes, documentation updates, dependency bumps | Fixing false positive, updating docs |

## Pre-Release Checklist

Before creating a release, verify the following:

### 1. Code Quality

- [ ] All CI checks pass on the `master` branch
- [ ] Test coverage meets or exceeds the configured threshold (currently 40%)
- [ ] No critical or high-severity findings from `vulnpredict scan vulnpredict/`
- [ ] Pre-commit hooks pass on all files: `pre-commit run --all-files`

### 2. Version Bump

Update the version in `pyproject.toml`:

```bash
# Edit pyproject.toml and change the version field
# Example: version = "0.3.0"
```

The version must be a valid [PEP 440](https://peps.python.org/pep-0440/) identifier:

- Release: `0.3.0`
- Release candidate: `0.3.0rc1`
- Beta: `0.3.0b1`
- Alpha: `0.3.0a1`
- Development (never published to PyPI): `0.3.0-dev`

### 3. Update CHANGELOG.md

Move entries from the `[Unreleased]` section to a new version section:

```markdown
## [0.3.0] - 2026-04-01

### Added
- Go analyzer with AST-based vulnerability detection
- HTML report generation

### Changed
- Improved taint analysis accuracy

### Fixed
- False positive in SQL injection detection
```

### 4. Update Documentation

- [ ] README.md reflects new features
- [ ] CLI help text is accurate (`vulnpredict --help`)
- [ ] CONTRIBUTING.md is current

### 5. Final Verification

```bash
# Run the full test suite
pytest tests/ -v

# Build the package locally
python -m build

# Test installation in a clean environment
python -m venv /tmp/release-test
/tmp/release-test/bin/pip install dist/vulnpredict-*.whl
/tmp/release-test/bin/vulnpredict --help
/tmp/release-test/bin/vulnpredict scan demo_project/
rm -rf /tmp/release-test
```

## Creating a Release

### Standard Release

1. **Create a release branch** (optional, for major/minor releases):

   ```bash
   git checkout -b release/v0.3.0
   # Make version bump and changelog updates
   git commit -am "chore: prepare release v0.3.0"
   git push origin release/v0.3.0
   # Create PR to master, get review, merge
   ```

2. **Create a GitHub Release**:

   - Go to [Releases](https://github.com/thehhugg/vulnpredict/releases/new)
   - Click **"Draft a new release"**
   - **Tag**: `v0.3.0` (create new tag on publish)
   - **Target**: `master`
   - **Title**: `v0.3.0`
   - **Description**: Copy the relevant section from CHANGELOG.md
   - Click **"Publish release"**

3. **Automated pipeline** (triggered by the release):

   The `release.yml` workflow will automatically:
   - Validate the tag version matches `pyproject.toml`
   - Build the sdist and wheel
   - Verify the package installs and the CLI works
   - Publish to PyPI via trusted publishing

4. **Verify the release**:

   ```bash
   pip install vulnpredict==0.3.0
   vulnpredict --help
   ```

### Release Candidate (RC)

For pre-release testing before a major or minor release:

1. Set version in `pyproject.toml` to `0.3.0rc1`
2. Create a GitHub Release:
   - **Tag**: `v0.3.0rc1`
   - Check **"Set as a pre-release"**
   - Click **"Publish release"**
3. The workflow publishes to both PyPI and TestPyPI
4. Test: `pip install vulnpredict==0.3.0rc1`
5. If issues are found, fix and release `0.3.0rc2`
6. When ready, release `0.3.0` as a standard release

### Hotfix Release

For urgent bug fixes on the latest release:

1. Create a branch from the release tag:

   ```bash
   git checkout -b hotfix/v0.3.1 v0.3.0
   ```

2. Apply the fix, bump to `0.3.1`, update CHANGELOG.md
3. Create PR to `master`, merge
4. Create a GitHub Release with tag `v0.3.1`

## Post-Release

After a successful release:

1. **Bump to next dev version**: Update `pyproject.toml` to `0.4.0-dev`
2. **Add new Unreleased section** to CHANGELOG.md
3. **Announce the release** (if applicable):
   - GitHub Discussions
   - Security tool directories
   - Social media

## Troubleshooting

### Release workflow failed

1. Check the [Actions tab](https://github.com/thehhugg/vulnpredict/actions/workflows/release.yml) for error details
2. Common issues:
   - **Version mismatch**: Tag version doesn't match `pyproject.toml` — fix the version and re-tag
   - **Build failure**: Package won't build — fix the issue, delete the release and tag, re-release
   - **PyPI publish failure**: Trusted publisher not configured — see [PyPI trusted publishing docs](https://docs.pypi.org/trusted-publishers/)

### Rolling back a release

PyPI does not allow re-uploading the same version. If a release has critical issues:

1. **Yank the release** on PyPI (marks it as not recommended but still installable)
2. Create a new patch release with the fix
