# Rule Authoring Guide

VulnPredict uses a YAML-based rule engine that allows users to define custom
vulnerability detection rules alongside the built-in rule set.

## Rule File Format

Each rule file must contain a top-level `rules` key with a list of rule
definitions:

```yaml
rules:
  - id: VULN001
    name: eval-injection
    severity: critical
    confidence: high
    languages: [python]
    message: "Use of eval() with potentially untrusted input"
    pattern:
      type: function_call
      name: eval
    cwe: CWE-95
    category: injection
    tags: [injection, rce]
    references:
      - https://cwe.mitre.org/data/definitions/95.html
```

## Field Reference

| Field | Required | Type | Description |
|---|---|---|---|
| `id` | Yes | string | Unique rule identifier (e.g., `VP-PY-001`) |
| `name` | Yes | string | Human-readable rule name |
| `severity` | Yes | string | One of: `critical`, `high`, `medium`, `low`, `info` |
| `message` | Yes | string | Description shown when the rule triggers |
| `pattern` | Yes | object | Detection pattern (see below) |
| `confidence` | No | string | One of: `high`, `medium`, `low` (default: `medium`) |
| `languages` | No | list | Target languages: `python`, `javascript`, `typescript`, `go` |
| `cwe` | No | string | CWE identifier (e.g., `CWE-79`) |
| `category` | No | string | Rule category for grouping |
| `tags` | No | list | Arbitrary tags for filtering |
| `references` | No | list | URLs with more information |
| `enabled` | No | boolean | Set to `false` to disable (default: `true`) |

## Pattern Types

### `function_call`

Matches calls to specific functions by name.

```yaml
# Single function
pattern:
  type: function_call
  name: eval

# Multiple functions (OR match)
pattern:
  type: function_call
  names:
    - pickle.loads
    - pickle.load
    - pickle.Unpickler
```

### `import` (planned)

Matches import statements.

### `attribute_access` (planned)

Matches attribute access patterns.

### `string_match` (planned)

Matches string patterns using regex.

## Using Custom Rules

### Via CLI

```bash
vulnpredict scan ./my-project --rules-dir ./my-rules
```

Multiple directories can be specified:

```bash
vulnpredict scan ./my-project --rules-dir ./team-rules --rules-dir ./project-rules
```

### Via Configuration File

In `.vulnpredict.yml`:

```yaml
rules:
  extra_dirs:
    - ./my-rules
    - /shared/security-rules
```

## Rule Precedence

When a user-defined rule has the same `id` as a built-in rule, the user rule
takes precedence. This allows you to override built-in rules (e.g., to change
severity or disable them).

## Built-in Rules

VulnPredict ships with rules in the `rules/` directory covering:

- **Injection**: eval, exec, os.system, subprocess, template injection
- **Deserialization**: pickle, yaml, marshal, jsonpickle
- **SSRF**: requests, urllib, httpx
- **Cryptography**: MD5, SHA1, DES
- **XXE**: XML parsing with external entities
- **Path traversal**: file operations with user-controlled paths
- **Open redirect**: redirect functions with user-controlled URLs
- **LDAP injection**: LDAP queries with untrusted input

## Tips

1. Use descriptive `id` values with a prefix (e.g., `MYORG-PY-001`)
2. Always include a `cwe` field for traceability
3. Set `confidence` based on false-positive likelihood
4. Use `tags` for filtering in CI pipelines
5. Test rules locally before deploying to your team
