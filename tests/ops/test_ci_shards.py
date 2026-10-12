"""Guard required dual-Python CI against coverage lost during sharding."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_ci_shards_preserve_original_required_dual_python_gates():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    jobs = workflow["jobs"]
    shard = jobs["validate-shards"]
    gate = jobs["validate"]
    assert shard["strategy"]["matrix"] == {
        "python-version": ["3.13", "3.14"],
        "suite": ["source-heavy", "everything-else"],
    }
    assert gate["strategy"]["matrix"]["python-version"] == ["3.13", "3.14"]
    assert gate["name"] == "Ubuntu 26.04 x86 / Python ${{ matrix.python-version }}"
    assert gate["needs"] == ["validate-shards"]
    gate_step = gate["steps"][0]
    assert 'SHARD_RESULT' in gate_step["env"]
    assert "success" in gate_step["run"]
    assert "exit 1" in gate_step["run"]
    assert "always()" in gate["if"]
    assert shard["timeout-minutes"] == 20
    assert gate["timeout-minutes"] == 5
    assert shard["runs-on"] == ["self-hosted", "linux", "x64", "ssh-over-mcp-mac-x86"]


def test_ci_shards_are_exact_complements_and_target_real_costly_tests():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    steps = workflow["jobs"]["validate-shards"]["steps"]
    run = next(step["run"] for step in steps if step["name"].startswith("Test "))
    match = re.search(r'^heavy="([^"]+)"$', run, flags=re.MULTILINE)
    assert match is not None
    selectors = match.group(1).split(" or ")
    assert len(selectors) == len(set(selectors)) >= 8
    tree = ast.parse((ROOT / "tests/ops/test_live_e2e_staging_projection.py").read_text())
    functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    assert set(selectors) <= functions
    target = "tests/ops/test_live_e2e_staging_projection.py"
    assert f'{target} -k "${{heavy}}"' in run
    assert f'{target} -k "not (${{heavy}})"' in run
    assert f"--ignore={target}" in run
    assert "case" in run and "esac" in run
