import os
import subprocess
import json

DANGEROUS_FUNCTIONS = {'eval', 'Function', 'setTimeout', 'setInterval'}
VALIDATION_FUNCTIONS = {'encodeURIComponent', 'escape', 'unescape', 'validator', 'sanitize', 'DOMPurify', 'decodeURIComponent'}

ESPRIMA_SCRIPT = '''
const esprima = require('esprima');
const fs = require('fs');
const file = process.argv[2];
const src = fs.readFileSync(file, 'utf8');
const ast = esprima.parseScript(src, { loc: true });
const findings = [];
function getMaxNestingDepth(node, current = 0) {
    if (!node.body || !Array.isArray(node.body)) return current;
    if (node.body.length === 0) return current;
    return Math.max(...node.body.map(child => getMaxNestingDepth(child, current + 1)), current);
}
function walk(node, parent) {
    if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression') {
        const length = node.body.body.length;
        let maxNesting = getMaxNestingDepth(node, 0);
        let inputValidation = [];
        esprima.traverse(node, {
            enter: function(child) {
                if (child.type === 'CallExpression' && child.callee.type === 'Identifier' && ['encodeURIComponent', 'escape', 'unescape', 'validator', 'sanitize', 'DOMPurify', 'decodeURIComponent'].includes(child.callee.name)) {
                    inputValidation.push(child.callee.name);
                }
            }
        });
        findings.push({
            type: 'function_analysis',
            name: node.id ? node.id.name : '<anonymous>',
            line: node.loc.start.line,
            length: length,
            max_nesting_depth: maxNesting,
            input_validation: inputValidation,
            dangerous_calls: []
        });
    }
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && ['eval', 'Function', 'setTimeout', 'setInterval'].includes(node.callee.name)) {
        findings.push({
            type: 'dangerous_call',
            function: node.callee.name,
            line: node.loc.start.line
        });
    }
    for (let key in node) {
        if (node[key] && typeof node[key] === 'object') {
            if (Array.isArray(node[key])) {
                node[key].forEach(child => child && walk(child, node));
            } else {
                walk(node[key], node);
            }
        }
    }
}
walk(ast, null);
console.log(JSON.stringify(findings));
'''

def analyze_js_file(filepath):
    """
    Analyze a JavaScript file for complexity and dangerous patterns using esprima.
    Returns a list of findings.
    """
    # Write the esprima script to a temp file
    import tempfile
    with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False) as f:
        f.write(ESPRIMA_SCRIPT)
        script_path = f.name
    try:
        result = subprocess.run([
            'node', script_path, filepath
        ], capture_output=True, text=True, check=True)
        findings = json.loads(result.stdout)
        return findings
    except Exception as e:
        print(f"[VulnPredict] JS analysis error: {e}")
        return []
    finally:
        os.remove(script_path)

def run_eslint(filepath):
    """
    Optionally run eslint on the given file and return parsed results.
    """
    try:
        result = subprocess.run([
            'eslint', '-f', 'json', filepath
        ], capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        findings = []
        for file_result in data:
            for msg in file_result.get('messages', []):
                findings.append({
                    'type': 'eslint',
                    'ruleId': msg.get('ruleId'),
                    'message': msg.get('message'),
                    'line': msg.get('line'),
                    'severity': msg.get('severity'),
                })
        return findings
    except Exception as e:
        print(f"[VulnPredict] ESLint error: {e}")
        return []

def extract_js_dependencies(path):
    """
    Extract dependencies from package.json if present in the root of the path.
    Returns a list of dependencies.
    """
    pkg_path = os.path.join(path, 'package.json')
    if os.path.exists(pkg_path):
        with open(pkg_path) as f:
            try:
                pkg = json.load(f)
                deps = list(pkg.get('dependencies', {}).keys())
                deps += list(pkg.get('devDependencies', {}).keys())
                return deps
            except Exception:
                return []
    return []

def analyze_js_project(path):
    """
    Recursively analyze all .js files in a directory.
    Returns a list of findings, including a dependencies finding if package.json is present.
    """
    findings = []
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith('.js'):
                fpath = os.path.join(root, file)
                findings.extend(analyze_js_file(fpath))
                findings.extend(run_eslint(fpath))
    # Add dependencies as a finding
    deps = extract_js_dependencies(path)
    if deps:
        findings.append({'type': 'dependencies', 'dependencies': deps})
    return findings 