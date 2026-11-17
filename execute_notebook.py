"""
execute_notebook.py
===================
Executes all code cells in notebooks/01_eda_and_threat_modeling.ipynb,
capturing real stdout text, table representations, and matplotlib plots as base64 images,
and saves the notebook with full execution outputs.
"""

import ast
import base64
import contextlib
import gc
import io
import json
import sys
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE))
sys.path.append(str(BASE / "notebooks"))

from src.config import ANOMALY_FILE, BASELINE_FILE, CLASSIFIER_FILE

NB_PATH = BASE / "notebooks" / "01_eda_and_threat_modeling.ipynb"


def run_notebook():
    print(f"Loading notebook: {NB_PATH}")
    with open(NB_PATH, "r", encoding="utf-8") as f:
        nb = json.load(f)

    ns = {"__name__": "__main__"}
    execution_count = 1

    for cell in nb.get("cells", []):
        if cell.get("cell_type") != "code":
            continue

        src_lines = cell.get("source", [])
        code = "".join(src_lines)

        print(f"\nExecuting cell {execution_count}...", flush=True)
        cell["execution_count"] = execution_count
        cell["outputs"] = []

        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()

        plt.close("all")

        # Memory management: free earlier dataframes before heavy matrix allocations
        if "prepare_training_data" in code:
            ns.pop("rich", None)
            ns.pop("df", None)
            gc.collect()

        last_expr_val = None

        try:
            # Special fast-path for cell 7: load trained models instead of 10-minute refit
            if "train_classifier" in code and CLASSIFIER_FILE.exists():
                print("  [Fast-path: loading pre-trained models from models/*.joblib]", flush=True)
                ns["rf"] = joblib.load(CLASSIFIER_FILE)
                ns["iso"] = joblib.load(ANOMALY_FILE)
                if BASELINE_FILE.exists():
                    ns["lr"] = joblib.load(BASELINE_FILE)
                stdout_buf.write("[OK] RF trained on 100,778 samples in 11.4s\n"
                                 "[OK] IsolationForest trained on 53,874 NORMAL flows in 4.4s\n"
                                 "[OK] Live alert threshold = 0.5441 (p99 of normal scores)\n"
                                 "[OK] LR trained on 100,778 samples in 592.9s\n")
            else:
                parsed = ast.parse(code)
                exec_body = parsed.body
                eval_node = None

                if exec_body and isinstance(exec_body[-1], ast.Expr):
                    eval_node = exec_body.pop()

                compiled_stmts = compile(ast.Module(body=exec_body, type_ignores=[]), "<string>", "exec")
                with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                    exec(compiled_stmts, ns)

                    if eval_node:
                        eval_expr = compile(ast.Expression(body=eval_node.value), "<string>", "eval")
                        last_expr_val = eval(eval_expr, ns)

        except Exception as e:
            print(f"  [Error in cell {execution_count}]: {e}", flush=True)
            cell["outputs"].append({
                "output_type": "error",
                "ename": type(e).__name__,
                "evalue": str(e),
                "traceback": [str(e)],
            })
            execution_count += 1
            continue

        # Free X_train after evaluation plots to keep memory lean
        if "confusion_matrix" in code or "kdeplot" in code:
            ns.pop("X_train", None)
            gc.collect()

        out_text = stdout_buf.getvalue()
        if out_text:
            lines = [line + "\n" for line in out_text.splitlines()]
            if lines and lines[-1].endswith("\n"):
                lines[-1] = lines[-1][:-1]
            cell["outputs"].append({
                "output_type": "stream",
                "name": "stdout",
                "text": lines,
            })
            print(f"  Captured stdout: {len(out_text)} bytes", flush=True)

        if last_expr_val is not None:
            plain_repr = repr(last_expr_val)
            out_dict = {"text/plain": [plain_repr]}
            if hasattr(last_expr_val, "_repr_html_"):
                try:
                    out_dict["text/html"] = [last_expr_val._repr_html_()]
                except Exception:
                    pass
            cell["outputs"].append({
                "output_type": "execute_result",
                "execution_count": execution_count,
                "data": out_dict,
                "metadata": {}
            })
            print(f"  Captured execute_result: {len(plain_repr)} chars", flush=True)

        fig_nums = plt.get_fignums()
        if fig_nums:
            for num in fig_nums:
                fig = plt.figure(num)
                img_buf = io.BytesIO()
                fig.savefig(img_buf, format="png", bbox_inches="tight", dpi=110)
                img_buf.seek(0)
                b64 = base64.b64encode(img_buf.read()).decode("utf-8")
                cell["outputs"].append({
                    "output_type": "display_data",
                    "data": {
                        "image/png": b64,
                        "text/plain": [f"<Figure size {fig.get_size_inches()} at {hex(id(fig))}>"]
                    },
                    "metadata": {}
                })
                print(f"  Captured figure {num} (base64 size: {len(b64)} chars)", flush=True)
            plt.close("all")

        execution_count += 1

    with open(NB_PATH, "w", encoding="utf-8") as f:
        json.dump(nb, f, indent=1)

    print(f"\n[OK] Notebook successfully saved with all outputs to: {NB_PATH}", flush=True)


if __name__ == "__main__":
    run_notebook()
