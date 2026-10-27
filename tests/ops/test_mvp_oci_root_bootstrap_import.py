"""OCI SSH root bootstrap must load only stdlib before dropping privileges."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HOST_AGENT_INIT = ROOT / "src/ssh_over_mcp/host_agent/__init__.py"


def test_root_phase_oci_import_works_in_isolated_python_without_third_party():
    script = (
        "import sys;"
        f"sys.path.insert(0,{str(ROOT / 'src')!r});"
        "from ssh_over_mcp.host_agent import oci_launcher_admission as adm;"
        "assert adm.OciLauncherDomain.for_node('node01').node == 'node01';"
        "assert 'pydantic' not in sys.modules;"
        "assert 'yaml' not in sys.modules;"
        "assert 'mcp' not in sys.modules"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_all_original_host_agent_exports_remain_lazy_and_resolvable():
    from ssh_over_mcp import host_agent

    tree = ast.parse(HOST_AGENT_INIT.read_text())
    mapping = next(
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "_EXPORT_MODULE"
            for target in node.targets
        )
    )
    assert set(mapping) == set(host_agent.__all__)
    for name in host_agent.__all__:
        assert getattr(host_agent, name) is not None


def test_unknown_public_name_is_not_imported():
    from ssh_over_mcp import host_agent

    with pytest.raises(AttributeError):
        host_agent.__getattr__("nonexistent_oci_privileged_entrypoint")
