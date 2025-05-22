import ast
import os
from collections import defaultdict, deque

DANGEROUS_FUNCTIONS = {'eval', 'exec', 'compile', 'execfile', 'input', 'os.system', 'subprocess.Popen', 'subprocess.call', 'cursor.execute', 'execute', 'os.popen', 'os.popen2', 'os.popen3', 'os.popen4'}
TAINT_SOURCES = {'input', 'os.environ', 'sys.argv', 'request.args', 'request.form', 'request.get_json', 'open', 'read', 'recv'}

class FunctionInfo:
    def __init__(self, name, args, node, calls, filename, lineno):
        self.name = name
        self.args = args
        self.node = node
        self.calls = calls  # list of (callee_name, arg_map, call_lineno)
        self.filename = filename
        self.lineno = lineno

class CallVisitor(ast.NodeVisitor):
    def __init__(self, func_args):
        self.calls = []  # (callee_name, arg_map, call_lineno)
        self.func_args = func_args

    def visit_Call(self, node):
        callee = self._get_func_name(node.func)
        arg_map = {}
        for i, arg in enumerate(node.args):
            if isinstance(arg, ast.Name):
                if i < len(self.func_args):
                    arg_map[self.func_args[i]] = arg.id
        self.calls.append((callee, arg_map, node.lineno))
        self.generic_visit(node)

    def _get_func_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_func_name(node.value)}.{node.attr}"
        return ''

def index_functions(path):
    """
    Parse all .py files and build a global function index and call graph.
    Returns: func_index (name -> FunctionInfo)
    """
    func_index = {}
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith('.py'):
                fpath = os.path.join(root, file)
                with open(fpath, 'r') as f:
                    source = f.read()
                try:
                    tree = ast.parse(source, filename=fpath)
                except Exception:
                    continue
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        func_name = f"{os.path.relpath(fpath, path)}::{node.name}"
                        args = [a.arg for a in node.args.args]
                        call_visitor = CallVisitor(args)
                        call_visitor.visit(node)
                        func_index[func_name] = FunctionInfo(
                            name=func_name,
                            args=args,
                            node=node,
                            calls=call_visitor.calls,
                            filename=fpath,
                            lineno=node.lineno
                        )
    return func_index

def find_taint_sources(node):
    sources = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Assign) and isinstance(child.value, ast.Call):
            func_name = CallVisitor([])._get_func_name(child.value.func)
            if func_name in TAINT_SOURCES:
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        sources.add(target.id)
    return sources

def find_sinks(node):
    sinks = []
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func_name = CallVisitor([])._get_func_name(child.func)
            if func_name in DANGEROUS_FUNCTIONS:
                sinks.append((func_name, child.lineno, child))
    return sinks

def analyze_project(path, max_depth=10):
    """
    Perform robust interprocedural taint analysis on a Python project.
    Returns a list of findings: each is a dict with source, sink, call_chain, and variable trace.
    """
    func_index = index_functions(path)
    findings = []
    # For each function, track taint propagation
    for func_name, finfo in func_index.items():
        sources = find_taint_sources(finfo.node)
        if not sources:
            continue
        # Worklist: (current_func, tainted_vars, call_chain, var_trace, depth)
        worklist = deque()
        worklist.append((func_name, set(sources), [func_name], [list(sources)], 0))
        visited = set()
        while worklist:
            curr_func, tainted, chain, trace, depth = worklist.popleft()
            if (curr_func, tuple(sorted(tainted))) in visited or depth > max_depth:
                continue
            visited.add((curr_func, tuple(sorted(tainted))))
            curr_info = func_index[curr_func]
            # Check for sinks
            for sink_name, sink_lineno, call_node in find_sinks(curr_info.node):
                for arg in getattr(call_node, 'args', []):
                    if isinstance(arg, ast.Name) and arg.id in tainted:
                        findings.append({
                            'type': 'interprocedural_taint',
                            'source_func': chain[0],
                            'sink_func': curr_func,
                            'sink': sink_name,
                            'sink_line': sink_lineno,
                            'call_chain': list(chain),
                            'tainted_var': arg.id,
                            'var_trace': [set(t) for t in trace],
                        })
            # Propagate taint through calls
            for callee, arg_map, call_lineno in curr_info.calls:
                if callee in func_index:
                    # If any argument passed is tainted, propagate
                    tainted_params = set()
                    for param, var in arg_map.items():
                        if var in tainted:
                            tainted_params.add(param)
                    if tainted_params:
                        worklist.append((
                            callee,
                            tainted_params,
                            chain + [callee],
                            trace + [tainted_params],
                            depth + 1
                        ))
    return findings 