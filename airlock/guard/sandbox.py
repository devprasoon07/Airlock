"""Demo-grade constrained execution for the run_code tool (S3).

Controls: AST-level blocked-import screening, subprocess timeout, isolated temp
working directory, captured output caps. This is NOT a container boundary —
documented as demo-grade; Docker is the stretch goal.
"""

from __future__ import annotations

import ast
import subprocess
import tempfile
from pathlib import Path
from typing import Any

BLOCKED_MODULES = {
    "socket", "os", "sys", "subprocess", "shutil", "pathlib",
    "http", "urllib", "requests", "pty", "signal", "ctypes",
    "multiprocessing", "threading", "importlib", "importlib_resources",
}

DEFAULT_TIMEOUT_S = 5
DEFAULT_MAX_OUTPUT = 4096


class _ImportVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.blocked: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            root = alias.name.split(".")[0]
            if root in BLOCKED_MODULES:
                self.blocked.append(alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.module:
            root = node.module.split(".")[0]
            if root in BLOCKED_MODULES:
                self.blocked.append(node.module)


def run_sandboxed(code: str, timeout: int = DEFAULT_TIMEOUT_S,
                  max_output: int = DEFAULT_MAX_OUTPUT) -> dict[str, Any]:
    """Execute `code` with static import screening + subprocess limits."""
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return {"stdout": "", "stderr": f"SyntaxError: {exc}", "timed_out": False,
                "blocked": None, "ok": False}

    visitor = _ImportVisitor()
    visitor.visit(tree)
    if visitor.blocked:
        return {"stdout": "", "stderr": "",
                "timed_out": False,
                "blocked": f"blocked imports: {', '.join(sorted(set(visitor.blocked)))}",
                "ok": False}

    with tempfile.TemporaryDirectory(prefix="airlock-sbox-") as tmp:
        target = Path(tmp) / "snippet.py"
        target.write_text(code, encoding="utf-8")
        try:
            proc = subprocess.run(
                ["python3", str(target)],
                cwd=tmp,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            out = proc.stdout[-max_output:]
            err = proc.stderr[-max_output:]
            return {"stdout": out, "stderr": err, "timed_out": False,
                    "blocked": None, "ok": proc.returncode == 0}
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout[-max_output:] if isinstance(exc.stdout, str) else ""
            return {"stdout": out, "stderr": f"killed after {timeout}s timeout",
                    "timed_out": True, "blocked": None, "ok": False}
