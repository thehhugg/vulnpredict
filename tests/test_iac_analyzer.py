"""Unit tests for the IaC analyzer (Terraform, Dockerfile, Kubernetes)."""

from __future__ import annotations

import textwrap
from typing import Any

import pytest

from vulnpredict.iac_analyzer import (
    scan_dockerfile,
    scan_iac_directory,
    scan_iac_file,
    scan_kubernetes_file,
    scan_terraform_file,
)


# ---------------------------------------------------------------------------
# Terraform tests
# ---------------------------------------------------------------------------


class TestTerraform:
    """Tests for Terraform security scanning."""

    def test_s3_without_encryption(self, tmp_path: Any) -> None:
        tf = textwrap.dedent('''\
            resource "aws_s3_bucket" "data" {
              bucket = "my-data-bucket"
              acl    = "private"
            }
        ''')
        f = tmp_path / "main.tf"
        f.write_text(tf)
        findings = scan_terraform_file(str(f))
        assert any(r["rule_id"] == "VP-TF-001" for r in findings)

    def test_s3_with_encryption_no_finding(self, tmp_path: Any) -> None:
        tf = textwrap.dedent('''\
            resource "aws_s3_bucket" "data" {
              bucket = "my-data-bucket"
              server_side_encryption_configuration {
                rule {
                  apply_server_side_encryption_by_default {
                    sse_algorithm = "AES256"
                  }
                }
              }
            }
        ''')
        f = tmp_path / "main.tf"
        f.write_text(tf)
        findings = scan_terraform_file(str(f))
        assert not any(r["rule_id"] == "VP-TF-001" for r in findings)

    def test_permissive_security_group(self, tmp_path: Any) -> None:
        tf = textwrap.dedent('''\
            resource "aws_security_group" "web" {
              ingress {
                from_port   = 0
                to_port     = 65535
                protocol    = "tcp"
                cidr_blocks = ["0.0.0.0/0"]
              }
            }
        ''')
        f = tmp_path / "sg.tf"
        f.write_text(tf)
        findings = scan_terraform_file(str(f))
        assert any(r["rule_id"] == "VP-TF-002" for r in findings)

    def test_iam_wildcard(self, tmp_path: Any) -> None:
        tf = textwrap.dedent('''\
            resource "aws_iam_policy" "admin" {
              policy = jsonencode({
                Statement = [{
                  Effect   = "Allow"
                  "Action" : "*"
                  Resource = "*"
                }]
              })
            }
        ''')
        f = tmp_path / "iam.tf"
        f.write_text(tf)
        findings = scan_terraform_file(str(f))
        assert any(r["rule_id"] == "VP-TF-003" for r in findings)

    def test_unencrypted_rds(self, tmp_path: Any) -> None:
        tf = textwrap.dedent('''\
            resource "aws_db_instance" "db" {
              engine         = "mysql"
              instance_class = "db.t3.micro"
            }
        ''')
        f = tmp_path / "rds.tf"
        f.write_text(tf)
        findings = scan_terraform_file(str(f))
        assert any(r["rule_id"] == "VP-TF-004" for r in findings)

    def test_encrypted_rds_no_finding(self, tmp_path: Any) -> None:
        tf = textwrap.dedent('''\
            resource "aws_db_instance" "db" {
              engine            = "mysql"
              instance_class    = "db.t3.micro"
              storage_encrypted = true
            }
        ''')
        f = tmp_path / "rds.tf"
        f.write_text(tf)
        findings = scan_terraform_file(str(f))
        assert not any(r["rule_id"] == "VP-TF-004" for r in findings)

    def test_ipv6_permissive(self, tmp_path: Any) -> None:
        tf = 'ipv6_cidr_blocks = ["::/0"]\n'
        f = tmp_path / "sg.tf"
        f.write_text(tf)
        findings = scan_terraform_file(str(f))
        assert any(r["rule_id"] == "VP-TF-005" for r in findings)

    def test_clean_terraform(self, tmp_path: Any) -> None:
        tf = textwrap.dedent('''\
            variable "region" {
              default = "us-east-1"
            }
        ''')
        f = tmp_path / "vars.tf"
        f.write_text(tf)
        findings = scan_terraform_file(str(f))
        assert len(findings) == 0

    def test_nonexistent_file(self) -> None:
        findings = scan_terraform_file("/nonexistent.tf")
        assert findings == []


# ---------------------------------------------------------------------------
# Dockerfile tests
# ---------------------------------------------------------------------------


class TestDockerfile:
    """Tests for Dockerfile security scanning."""

    def test_no_user_directive(self, tmp_path: Any) -> None:
        dockerfile = textwrap.dedent("""\
            FROM python:3.11
            RUN pip install flask
            CMD ["python", "app.py"]
        """)
        f = tmp_path / "Dockerfile"
        f.write_text(dockerfile)
        findings = scan_dockerfile(str(f))
        assert any(r["rule_id"] == "VP-DF-001" for r in findings)

    def test_with_user_directive(self, tmp_path: Any) -> None:
        dockerfile = textwrap.dedent("""\
            FROM python:3.11
            RUN pip install flask
            USER appuser
            CMD ["python", "app.py"]
        """)
        f = tmp_path / "Dockerfile"
        f.write_text(dockerfile)
        findings = scan_dockerfile(str(f))
        assert not any(r["rule_id"] == "VP-DF-001" for r in findings)

    def test_latest_tag(self, tmp_path: Any) -> None:
        dockerfile = "FROM python:latest\n"
        f = tmp_path / "Dockerfile"
        f.write_text(dockerfile)
        findings = scan_dockerfile(str(f))
        assert any(r["rule_id"] == "VP-DF-002" for r in findings)

    def test_no_tag(self, tmp_path: Any) -> None:
        dockerfile = "FROM python\n"
        f = tmp_path / "Dockerfile"
        f.write_text(dockerfile)
        findings = scan_dockerfile(str(f))
        assert any(r["rule_id"] == "VP-DF-003" for r in findings)

    def test_copy_secrets(self, tmp_path: Any) -> None:
        dockerfile = textwrap.dedent("""\
            FROM python:3.11
            COPY .env /app/.env
            USER appuser
        """)
        f = tmp_path / "Dockerfile"
        f.write_text(dockerfile)
        findings = scan_dockerfile(str(f))
        assert any(r["rule_id"] == "VP-DF-004" for r in findings)

    def test_add_remote_url(self, tmp_path: Any) -> None:
        dockerfile = textwrap.dedent("""\
            FROM python:3.11
            ADD https://example.com/file.tar.gz /app/
            USER appuser
        """)
        f = tmp_path / "Dockerfile"
        f.write_text(dockerfile)
        findings = scan_dockerfile(str(f))
        assert any(r["rule_id"] == "VP-DF-005" for r in findings)

    def test_explicit_root_user(self, tmp_path: Any) -> None:
        dockerfile = textwrap.dedent("""\
            FROM python:3.11
            USER root
        """)
        f = tmp_path / "Dockerfile"
        f.write_text(dockerfile)
        findings = scan_dockerfile(str(f))
        assert any(r["rule_id"] == "VP-DF-006" for r in findings)

    def test_pinned_version_no_finding(self, tmp_path: Any) -> None:
        dockerfile = textwrap.dedent("""\
            FROM python:3.11-slim
            USER appuser
            CMD ["python", "app.py"]
        """)
        f = tmp_path / "Dockerfile"
        f.write_text(dockerfile)
        findings = scan_dockerfile(str(f))
        assert len(findings) == 0

    def test_nonexistent_file(self) -> None:
        findings = scan_dockerfile("/nonexistent/Dockerfile")
        assert findings == []


# ---------------------------------------------------------------------------
# Kubernetes tests
# ---------------------------------------------------------------------------


class TestKubernetes:
    """Tests for Kubernetes manifest scanning."""

    def test_privileged_container(self, tmp_path: Any) -> None:
        manifest = textwrap.dedent("""\
            apiVersion: v1
            kind: Pod
            spec:
              containers:
              - name: app
                securityContext:
                  privileged: true
        """)
        f = tmp_path / "pod.yaml"
        f.write_text(manifest)
        findings = scan_kubernetes_file(str(f))
        assert any(r["rule_id"] == "VP-K8-001" for r in findings)

    def test_run_as_root(self, tmp_path: Any) -> None:
        manifest = textwrap.dedent("""\
            apiVersion: v1
            kind: Pod
            spec:
              containers:
              - name: app
                securityContext:
                  runAsUser: 0
        """)
        f = tmp_path / "pod.yaml"
        f.write_text(manifest)
        findings = scan_kubernetes_file(str(f))
        assert any(r["rule_id"] == "VP-K8-002" for r in findings)

    def test_host_network(self, tmp_path: Any) -> None:
        manifest = textwrap.dedent("""\
            apiVersion: v1
            kind: Pod
            spec:
              hostNetwork: true
              containers:
              - name: app
        """)
        f = tmp_path / "pod.yaml"
        f.write_text(manifest)
        findings = scan_kubernetes_file(str(f))
        assert any(r["rule_id"] == "VP-K8-003" for r in findings)

    def test_host_pid(self, tmp_path: Any) -> None:
        manifest = textwrap.dedent("""\
            apiVersion: v1
            kind: Pod
            spec:
              hostPID: true
              containers:
              - name: app
        """)
        f = tmp_path / "pod.yaml"
        f.write_text(manifest)
        findings = scan_kubernetes_file(str(f))
        assert any(r["rule_id"] == "VP-K8-004" for r in findings)

    def test_missing_resource_limits(self, tmp_path: Any) -> None:
        manifest = textwrap.dedent("""\
            apiVersion: v1
            kind: Pod
            spec:
              containers:
              - name: app
                image: nginx
        """)
        f = tmp_path / "pod.yaml"
        f.write_text(manifest)
        findings = scan_kubernetes_file(str(f))
        assert any(r["rule_id"] == "VP-K8-005" for r in findings)

    def test_with_resource_limits(self, tmp_path: Any) -> None:
        manifest = textwrap.dedent("""\
            apiVersion: v1
            kind: Pod
            spec:
              containers:
              - name: app
                resources:
                  limits:
                    memory: "128Mi"
                    cpu: "500m"
        """)
        f = tmp_path / "pod.yaml"
        f.write_text(manifest)
        findings = scan_kubernetes_file(str(f))
        assert not any(r["rule_id"] == "VP-K8-005" for r in findings)

    def test_allow_privilege_escalation(self, tmp_path: Any) -> None:
        manifest = textwrap.dedent("""\
            apiVersion: v1
            kind: Pod
            spec:
              containers:
              - name: app
                securityContext:
                  allowPrivilegeEscalation: true
        """)
        f = tmp_path / "pod.yaml"
        f.write_text(manifest)
        findings = scan_kubernetes_file(str(f))
        assert any(r["rule_id"] == "VP-K8-006" for r in findings)

    def test_non_k8s_yaml(self, tmp_path: Any) -> None:
        yaml = textwrap.dedent("""\
            name: my-config
            settings:
              debug: true
        """)
        f = tmp_path / "config.yaml"
        f.write_text(yaml)
        findings = scan_kubernetes_file(str(f))
        assert len(findings) == 0

    def test_secure_pod(self, tmp_path: Any) -> None:
        manifest = textwrap.dedent("""\
            apiVersion: v1
            kind: Pod
            spec:
              containers:
              - name: app
                securityContext:
                  runAsUser: 1000
                  allowPrivilegeEscalation: false
                resources:
                  limits:
                    memory: "128Mi"
                    cpu: "500m"
        """)
        f = tmp_path / "pod.yaml"
        f.write_text(manifest)
        findings = scan_kubernetes_file(str(f))
        assert len(findings) == 0

    def test_nonexistent_file(self) -> None:
        findings = scan_kubernetes_file("/nonexistent.yaml")
        assert findings == []


# ---------------------------------------------------------------------------
# scan_iac_file dispatch tests
# ---------------------------------------------------------------------------


class TestIacFileDispatch:
    """Tests for the scan_iac_file dispatch function."""

    def test_dispatch_terraform(self, tmp_path: Any) -> None:
        f = tmp_path / "main.tf"
        f.write_text('cidr_blocks = ["0.0.0.0/0"]\n')
        findings = scan_iac_file(str(f))
        assert any(r["rule_id"] == "VP-TF-002" for r in findings)

    def test_dispatch_dockerfile(self, tmp_path: Any) -> None:
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:latest\n")
        findings = scan_iac_file(str(f))
        assert any(r["rule_id"] == "VP-DF-002" for r in findings)

    def test_dispatch_kubernetes(self, tmp_path: Any) -> None:
        f = tmp_path / "deploy.yaml"
        f.write_text("apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: x\n    securityContext:\n      privileged: true\n")
        findings = scan_iac_file(str(f))
        assert any(r["rule_id"] == "VP-K8-001" for r in findings)

    def test_dispatch_unknown_extension(self, tmp_path: Any) -> None:
        f = tmp_path / "readme.md"
        f.write_text("# Hello\n")
        findings = scan_iac_file(str(f))
        assert findings == []


# ---------------------------------------------------------------------------
# Directory scanning tests
# ---------------------------------------------------------------------------


class TestDirectoryScan:
    """Tests for directory-level IaC scanning."""

    def test_scan_mixed_directory(self, tmp_path: Any) -> None:
        (tmp_path / "main.tf").write_text('cidr_blocks = ["0.0.0.0/0"]\n')
        (tmp_path / "Dockerfile").write_text("FROM python:latest\n")
        k8s = tmp_path / "k8s"
        k8s.mkdir()
        (k8s / "pod.yaml").write_text(
            "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: x\n    securityContext:\n      privileged: true\n"
        )
        findings = scan_iac_directory(str(tmp_path))
        rule_ids = {f["rule_id"] for f in findings}
        assert "VP-TF-002" in rule_ids
        assert "VP-DF-002" in rule_ids
        assert "VP-K8-001" in rule_ids

    def test_skip_terraform_dir(self, tmp_path: Any) -> None:
        tf_dir = tmp_path / ".terraform" / "modules"
        tf_dir.mkdir(parents=True)
        (tf_dir / "main.tf").write_text('cidr_blocks = ["0.0.0.0/0"]\n')
        findings = scan_iac_directory(str(tmp_path))
        assert len(findings) == 0

    def test_empty_directory(self, tmp_path: Any) -> None:
        findings = scan_iac_directory(str(tmp_path))
        assert findings == []
