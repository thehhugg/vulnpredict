import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os
import numpy as np

def extract_features(findings):
    """
    Convert analyzer findings (list of dicts) to a DataFrame of features for ML.
    Ensures only numeric columns are returned, and fills NaN/inf with 0.
    """
    rows = []
    max_embedding_len = 0
    for f in findings:
        row = {
            'length': f.get('length', 0),
            'dangerous_calls': len(f.get('dangerous_calls', [])),
            'cyclomatic_complexity': float(f.get('cyclomatic_complexity', 0) or 0),
            'max_nesting_depth': float(f.get('max_nesting_depth', 0) or 0),
            'input_validation': float(len(f.get('input_validation', [])) or 0),
            'dependency_count': float(len(f.get('dependencies', [])) if f.get('type') == 'dependencies' else 0),
            # Taint analysis features
            'taint_path_to_sink': float(1 if f.get('type') == 'taint_analysis' else 0),
            'taint_path_length': float(len(f.get('trace', [])) if f.get('type') == 'taint_analysis' else 0),
            # Interprocedural taint features
            'interprocedural_taint_path': float(1 if f.get('type') == 'interprocedural_taint' else 0),
            'interprocedural_call_chain_length': float(len(f.get('call_chain', [])) if f.get('type') == 'interprocedural_taint' else 0),
            'interprocedural_var_trace_length': float(len(f.get('var_trace', [])) if f.get('type') == 'interprocedural_taint' else 0),
            # Code churn features
            'commit_count': float(f.get('commit_count', 0) or 0),
            'unique_authors': float(f.get('unique_authors', 0) or 0),
            'last_modified_days': float(f.get('last_modified_days', 0) or 0),
            # Dependency risk features
            'num_vulnerable_dependencies': float(f.get('num_vulnerable_dependencies', 0) if f.get('type') == 'dependencies' else 0),
            'num_outdated_dependencies': float(f.get('num_outdated_dependencies', 0) if f.get('type') == 'dependencies' else 0),
            'max_dependency_severity': float(f.get('max_dependency_severity', 0) if f.get('type') == 'dependencies' else 0),
            # Sensitive data features
            'sensitive_data_involved': float(int(f.get('sensitive_data_involved', False))),
            'num_sensitive_vars': float(f.get('num_sensitive_vars', 0) or 0),
        }
        # Add embedding features if present
        embedding = f.get('embedding')
        if embedding:
            for i, val in enumerate(embedding):
                try:
                    row[f'embedding_{i}'] = float(val)
                except Exception:
                    row[f'embedding_{i}'] = 0.0
            max_embedding_len = max(max_embedding_len, len(embedding))
        rows.append(row)
    # Pad missing embedding dimensions with 0
    for row in rows:
        for i in range(max_embedding_len):
            if f'embedding_{i}' not in row:
                row[f'embedding_{i}'] = 0.0
    # Add a global feature: number of taint findings in the project
    taint_count = sum(1 for f in findings if f.get('type') == 'taint_analysis')
    for row in rows:
        row['taint_finding_count'] = float(taint_count)
    df = pd.DataFrame(rows)
    # Keep only numeric columns and fill NaN/inf with 0
    df = df.select_dtypes(include=[np.number])
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)
    return df

def train_model(features, labels, model_path='vulnpredict_model.joblib'):
    """
    Train a RandomForest model and save it to disk.
    Handles very small datasets by training/testing on all data if needed.
    """
    print("[VulnPredict] Training features preview:")
    print(features.head())
    print("[VulnPredict] Training labels preview:")
    print(labels.head())
    if len(features) < 5:
        print("[VulnPredict] WARNING: Very few samples. Training and testing on all data.")
        X_train, y_train = features, labels
        X_test, y_test = features, labels
    else:
        X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))
    joblib.dump(clf, model_path)
    print(f"[VulnPredict] Model saved to {model_path}")
    return clf

def load_model(model_path='vulnpredict_model.joblib'):
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found: {model_path}")
    return joblib.load(model_path)

def predict(findings, model_path='vulnpredict_model.joblib'):
    """
    Score new findings using the trained model.
    Returns a list of (finding, score) tuples.
    """
    model = load_model(model_path)
    features = extract_features(findings)
    scores = model.predict_proba(features)[:, 1]  # Probability of class 1 (vulnerable)
    results = []
    for f, score in zip(findings, scores):
        results.append({**f, 'vuln_score': score})
    return results 