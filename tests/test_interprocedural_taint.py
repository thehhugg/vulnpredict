"""Unit tests for vulnpredict/interprocedural_taint.py.

Tests cover:
- index_functions: building the function index from a project directory
- find_taint_sources: detecting taint sources within function AST nodes
- find_sinks: detecting dangerous function calls within function AST nodes
- CallVisitor: extracting function calls and argument mappings
- analyze_project: end-to-end interprocedural taint analysis
- Edge cases: empty projects, syntax errors, no taint

Known limitation: The current interprocedural analysis indexes functions with
keys like 'filename.py::func_name', but callee lookups use bare function names
(e.g., 'process_data'). This means cross-function taint propagation only works
when the callee key matches the bare call name — which requires functions to be
in the same file with matching key format. Tests document this behavior.
"""

import ast
import os
import shutil
import tempfile

import pytest

from vulnpredict.interprocedural_taint import (
    CallVisitor,
    FunctionInfo,
    analyze_project,
    find_sinks,
    find_taint_sources,
    index_functions,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "taint")


# =========================================================================
# Test: CallVisitor
# =========================================================================
class TestCallVisitor:
    """Verify CallVisitor extracts function calls from AST nodes."""

    def test_extracts_simple_call(self):
        code = "eval(x)"
        tree = ast.parse(code)
        visitor = CallVisitor(["x"])
        visitor.visit(tree)
        assert len(visitor.calls) == 1
        assert visitor.calls[0][0] == "eval"

    def test_extracts_attribute_call(self):
        code = "cursor.execute(query)"
        tree = ast.parse(code)
        visitor = CallVisitor(["query"])
        visitor.visit(tree)
        assert len(visitor.calls) == 1
        assert visitor.calls[0][0] == "cursor.execute"

    def test_extracts_call_lineno(self):
        code = "x = 1\neval(x)"
        tree = ast.parse(code)
        visitor = CallVisitor(["x"])
        visitor.visit(tree)
        assert visitor.calls[0][2] == 2  # line number

    def test_extracts_arg_map_for_matching_params(self):
        code = "def foo(a, b):\n    bar(a)"
        tree = ast.parse(code)
        func_node = tree.body[0]
        visitor = CallVisitor(["a", "b"])
        visitor.visit(func_node)
        assert len(visitor.calls) == 1
        callee, arg_map, _ = visitor.calls[0]
        assert callee == "bar"
        assert "a" in arg_map

    def test_no_calls_in_empty_function(self):
        code = "def foo():\n    pass"
        tree = ast.parse(code)
        visitor = CallVisitor([])
        visitor.visit(tree)
        assert len(visitor.calls) == 0

    def test_nested_attribute_call(self):
        code = "os.path.join(a, b)"
        tree = ast.parse(code)
        visitor = CallVisitor([])
        visitor.visit(tree)
        assert len(visitor.calls) == 1
        assert visitor.calls[0][0] == "os.path.join"

    def test_get_func_name_returns_empty_for_complex_expr(self):
        # e.g., foo()() — a call on a call result
        code = "foo()(x)"
        tree = ast.parse(code)
        visitor = CallVisitor([])
        visitor.visit(tree)
        # The outer call has a Call as func, which should return ""
        names = [c[0] for c in visitor.calls]
        assert "" in names


# =========================================================================
# Test: index_functions
# =========================================================================
class TestIndexFunctions:
    """Verify index_functions builds a correct function index."""

    def test_indexes_functions_from_fixture(self):
        func_index = index_functions(FIXTURES_DIR)
        func_names = list(func_index.keys())
        has_get_input = any("get_user_input" in n for n in func_names)
        has_process = any("process_data" in n for n in func_names)
        assert has_get_input
        assert has_process

    def test_function_key_format(self):
        """Function keys use 'relative_path::func_name' format."""
        func_index = index_functions(FIXTURES_DIR)
        for key in func_index:
            assert "::" in key, f"Key '{key}' should contain '::'"

    def test_function_info_has_args(self):
        func_index = index_functions(FIXTURES_DIR)
        process_funcs = {k: v for k, v in func_index.items() if "process_data" in k}
        assert len(process_funcs) >= 1
        func_info = list(process_funcs.values())[0]
        assert "value" in func_info.args

    def test_function_info_has_calls(self):
        func_index = index_functions(FIXTURES_DIR)
        get_input_funcs = {k: v for k, v in func_index.items() if "get_user_input" in k}
        assert len(get_input_funcs) >= 1
        func_info = list(get_input_funcs.values())[0]
        callee_names = [c[0] for c in func_info.calls]
        assert "process_data" in callee_names

    def test_function_info_has_filename(self):
        func_index = index_functions(FIXTURES_DIR)
        for info in func_index.values():
            assert os.path.isfile(info.filename)

    def test_function_info_has_lineno(self):
        func_index = index_functions(FIXTURES_DIR)
        for info in func_index.values():
            assert isinstance(info.lineno, int)
            assert info.lineno >= 1

    def test_empty_directory_returns_empty(self):
        tmpdir = tempfile.mkdtemp()
        try:
            func_index = index_functions(tmpdir)
            assert func_index == {}
        finally:
            shutil.rmtree(tmpdir)

    def test_ignores_non_python_files(self):
        tmpdir = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmpdir, "readme.md"), "w") as f:
                f.write("# Hello")
            func_index = index_functions(tmpdir)
            assert func_index == {}
        finally:
            shutil.rmtree(tmpdir)

    def test_handles_syntax_error_gracefully(self):
        tmpdir = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmpdir, "broken.py"), "w") as f:
                f.write("def broken(\n")
            func_index = index_functions(tmpdir)
            assert func_index == {}
        finally:
            shutil.rmtree(tmpdir)


# =========================================================================
# Test: find_taint_sources
# =========================================================================
class TestFindTaintSources:
    """Verify find_taint_sources detects taint source assignments."""

    def test_detects_input_source(self):
        code = "data = input('Enter: ')"
        tree = ast.parse(code)
        sources = find_taint_sources(tree)
        assert "data" in sources

    def test_detects_open_source(self):
        code = "f = open('file.txt')"
        tree = ast.parse(code)
        sources = find_taint_sources(tree)
        assert "f" in sources

    def test_no_sources_in_safe_code(self):
        code = "x = 42\ny = 'hello'"
        tree = ast.parse(code)
        sources = find_taint_sources(tree)
        assert len(sources) == 0

    def test_detects_multiple_sources(self):
        code = "a = input('x')\nb = open('y')"
        tree = ast.parse(code)
        sources = find_taint_sources(tree)
        assert "a" in sources
        assert "b" in sources

    def test_does_not_detect_non_source_call(self):
        """Calls not in TAINT_SOURCES should not be detected."""
        code = "x = len('hello')"
        tree = ast.parse(code)
        sources = find_taint_sources(tree)
        assert len(sources) == 0

    def test_request_args_get_not_detected(self):
        """request.args.get() resolves to 'request.args.get', not 'request.args'.
        This is a known limitation — the exact function name must match TAINT_SOURCES."""
        code = "q = request.args.get('q')"
        tree = ast.parse(code)
        sources = find_taint_sources(tree)
        assert "q" not in sources  # Known limitation


# =========================================================================
# Test: find_sinks
# =========================================================================
class TestFindSinks:
    """Verify find_sinks detects dangerous function calls."""

    def test_detects_eval_sink(self):
        code = "eval(x)"
        tree = ast.parse(code)
        sinks = find_sinks(tree)
        assert len(sinks) >= 1
        sink_names = [s[0] for s in sinks]
        assert "eval" in sink_names

    def test_detects_exec_sink(self):
        code = "exec(code)"
        tree = ast.parse(code)
        sinks = find_sinks(tree)
        sink_names = [s[0] for s in sinks]
        assert "exec" in sink_names

    def test_detects_cursor_execute_sink(self):
        code = "cursor.execute(query)"
        tree = ast.parse(code)
        sinks = find_sinks(tree)
        sink_names = [s[0] for s in sinks]
        assert "cursor.execute" in sink_names

    def test_detects_os_system_sink(self):
        code = "os.system(cmd)"
        tree = ast.parse(code)
        sinks = find_sinks(tree)
        sink_names = [s[0] for s in sinks]
        assert "os.system" in sink_names

    def test_no_sinks_in_safe_code(self):
        code = "print('hello')\nx = 42"
        tree = ast.parse(code)
        sinks = find_sinks(tree)
        assert len(sinks) == 0

    def test_sink_has_line_number(self):
        code = "x = 1\neval(x)"
        tree = ast.parse(code)
        sinks = find_sinks(tree)
        assert sinks[0][1] == 2

    def test_sink_has_call_node(self):
        code = "eval(x)"
        tree = ast.parse(code)
        sinks = find_sinks(tree)
        assert isinstance(sinks[0][2], ast.Call)


# =========================================================================
# Test: analyze_project — interprocedural taint analysis
# =========================================================================
class TestAnalyzeProject:
    """Verify end-to-end interprocedural taint analysis.

    Note: Due to the callee key mismatch limitation (function index uses
    'filename::funcname' but callee lookups use bare names), cross-function
    propagation does not currently work for the standard fixtures. These tests
    document the current behavior.
    """

    def test_safe_project_has_no_findings(self):
        tmpdir = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmpdir, "safe.py"), "w") as f:
                f.write("def compute(x):\n    return x * 2\n\ndef main():\n    print(compute(42))\n")
            findings = analyze_project(tmpdir)
            assert len(findings) == 0
        finally:
            shutil.rmtree(tmpdir)

    def test_empty_project_returns_empty(self):
        tmpdir = tempfile.mkdtemp()
        try:
            findings = analyze_project(tmpdir)
            assert findings == []
        finally:
            shutil.rmtree(tmpdir)

    def test_intra_function_taint_detected(self):
        """Taint within a single function (source and sink in same function) is detected."""
        tmpdir = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmpdir, "vuln.py"), "w") as f:
                f.write("def dangerous():\n    data = input('x')\n    eval(data)\n")
            findings = analyze_project(tmpdir)
            interproc = [f for f in findings if f["type"] == "interprocedural_taint"]
            assert len(interproc) >= 1
            assert interproc[0]["sink"] == "eval"
            assert interproc[0]["tainted_var"] == "data"
        finally:
            shutil.rmtree(tmpdir)

    def test_finding_has_all_required_keys(self):
        tmpdir = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmpdir, "vuln.py"), "w") as f:
                f.write("def dangerous():\n    data = input('x')\n    eval(data)\n")
            findings = analyze_project(tmpdir)
            interproc = [f for f in findings if f["type"] == "interprocedural_taint"]
            assert len(interproc) >= 1
            required_keys = {
                "type", "source_func", "sink_func", "sink",
                "sink_line", "call_chain", "tainted_var", "var_trace",
            }
            for finding in interproc:
                assert required_keys.issubset(finding.keys()), (
                    f"Missing keys: {required_keys - finding.keys()}"
                )
        finally:
            shutil.rmtree(tmpdir)

    def test_finding_call_chain_includes_source_func(self):
        tmpdir = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmpdir, "vuln.py"), "w") as f:
                f.write("def dangerous():\n    data = input('x')\n    eval(data)\n")
            findings = analyze_project(tmpdir)
            interproc = [f for f in findings if f["type"] == "interprocedural_taint"]
            assert len(interproc) >= 1
            # call_chain should at least include the source function
            assert len(interproc[0]["call_chain"]) >= 1
        finally:
            shutil.rmtree(tmpdir)

    def test_var_trace_is_list_of_sets(self):
        tmpdir = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmpdir, "vuln.py"), "w") as f:
                f.write("def dangerous():\n    data = input('x')\n    eval(data)\n")
            findings = analyze_project(tmpdir)
            interproc = [f for f in findings if f["type"] == "interprocedural_taint"]
            assert len(interproc) >= 1
            trace = interproc[0]["var_trace"]
            assert isinstance(trace, list)
            assert all(isinstance(t, set) for t in trace)
        finally:
            shutil.rmtree(tmpdir)

    def test_max_depth_limits_recursion(self):
        """Verify that max_depth parameter prevents infinite recursion."""
        tmpdir = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmpdir, "vuln.py"), "w") as f:
                f.write("def dangerous():\n    data = input('x')\n    eval(data)\n")
            # Should complete without hanging
            findings = analyze_project(tmpdir, max_depth=2)
            assert isinstance(findings, list)
        finally:
            shutil.rmtree(tmpdir)

    def test_cross_function_propagation_limitation(self):
        """Document that cross-function taint propagation doesn't work due to
        key format mismatch (filename::funcname vs bare funcname).
        This test documents the current behavior, not the desired behavior."""
        findings = analyze_project(FIXTURES_DIR)
        interproc = [f for f in findings if f["type"] == "interprocedural_taint"]
        # Due to the key mismatch, cross-function propagation from
        # get_user_input -> process_data doesn't work.
        # Only intra-function findings (source + sink in same function) are detected.
        cross_func = [f for f in interproc if len(f["call_chain"]) > 1]
        # Currently no cross-function findings due to the limitation
        assert len(cross_func) == 0


class TestFunctionInfo:
    """Verify FunctionInfo data class behavior."""

    def test_function_info_stores_attributes(self):
        info = FunctionInfo(
            name="test::foo",
            args=["a", "b"],
            node=None,
            calls=[("bar", {"a": "x"}, 5)],
            filename="test.py",
            lineno=1,
        )
        assert info.name == "test::foo"
        assert info.args == ["a", "b"]
        assert info.filename == "test.py"
        assert info.lineno == 1
        assert len(info.calls) == 1
