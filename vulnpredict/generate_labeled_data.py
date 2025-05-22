import click
import pandas as pd
from .py_analyzer import analyze_python_project
from .js_analyzer import analyze_js_project
from .interprocedural_taint import analyze_project as analyze_interprocedural_taint

def auto_label(finding):
    # Heuristic: label as vulnerable if dangerous_calls, high complexity, high nesting, or interprocedural taint
    if finding.get('dangerous_calls') or finding.get('cyclomatic_complexity', 0) > 10 or finding.get('max_nesting_depth', 0) > 5:
        return 1
    if finding.get('type') == 'interprocedural_taint':
        return 1
    return 0

@click.command()
@click.argument('code_dir')
@click.argument('output_csv')
def main(code_dir, output_csv):
    """
    Analyze CODE_DIR, label findings, and save to OUTPUT_CSV for ML training.
    """
    py_findings = analyze_python_project(code_dir)
    js_findings = analyze_js_project(code_dir)
    interproc_findings = analyze_interprocedural_taint(code_dir)
    all_findings = py_findings + js_findings + interproc_findings
    for f in all_findings:
        f['label'] = auto_label(f)
    df = pd.DataFrame(all_findings)
    df.to_csv(output_csv, index=False)
    print(f"[VulnPredict] Labeled data saved to {output_csv}")

if __name__ == '__main__':
    main() 