from __future__ import annotations

import subprocess
import sys


def test_execution_authorizer_imports_in_clean_interpreter() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from ssh_over_mcp.approvals.authorization "
                "import ExecutionAuthorizer, ExecutionAuthorizationGate; "
                "assert ExecutionAuthorizer is not None; "
                "assert ExecutionAuthorizationGate is not None"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
