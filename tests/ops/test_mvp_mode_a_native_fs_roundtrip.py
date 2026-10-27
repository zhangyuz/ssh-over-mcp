"""Real Linux host-agent CLI filesystem roundtrip, no Docker or SSH server.

Uses the *actual* candidate policy schema and protocol framing, replacing
only the fixed /srv/data root with two disposable pytest roots. The existing
OCI guest/SSH acceptance remains a separate mandatory gate.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.cli import EX_NOPERM, EX_UNAVAILABLE, run
from ssh_over_mcp.host_agent.policy import (
    HostFilesystemProfilePolicy,
    load_host_policy,
)
from ssh_over_mcp.ssh.protocol import (
    ExecEnvelope,
    ExecutionLimits,
    FsMkdirEnvelope,
    FsReadEnvelope,
    FsStatEnvelope,
    FsWriteEnvelope,
    encode_request,
)

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / "deploy/ssh-target/host-policy.review-candidate.yaml"
PROFILE = "rw-operator"


def _node_policy(data_root: Path):
    """Same FS-only candidate, re-rooted solely to a disposable test path."""
    policy = load_host_policy(CANDIDATE, require_root_owner=False)
    expected = policy.filesystem[PROFILE]
    assert (
        expected.stat_roots,
        expected.read_roots,
        expected.mkdir_roots,
        expected.write_create_roots,
    ) == (("/srv/data",),) * 4
    assert expected.max_read_bytes == expected.max_write_bytes == 4096
    return policy.model_copy(
        update={
            "filesystem": {
                PROFILE: HostFilesystemProfilePolicy(
                    stat_roots=(str(data_root),),
                    read_roots=(str(data_root),),
                    mkdir_roots=(str(data_root),),
                    write_create_roots=(str(data_root),),
                    max_read_bytes=4096,
                    max_write_bytes=4096,
                )
            }
        }
    )


def _request(policy, envelope, body: bytes = b"") -> tuple[int, bytes, str]:
    stdout, errors = io.BytesIO(), io.StringIO()
    result = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(encode_request(envelope, body)),
        stdout=stdout,
        stderr=errors,
        execution_stderr=io.BytesIO(),
        policy=policy,
    )
    return result, stdout.getvalue(), errors.getvalue()


@pytest.mark.skipif(sys.platform != "linux", reason="requires real Linux O_PATH/dirfd/fsync")
def test_two_node_fs_roundtrip_uses_real_host_agent_and_kernel(tmp_path: Path):
    nodes = tuple(tmp_path / n / "data" for n in ("node01", "node02"))
    for root in nodes:
        root.mkdir(parents=True)
    policies = tuple(_node_policy(root) for root in nodes)
    payloads = (b"node01-MCP-hello\x00", b"node02-MCP-hello\xff")

    for i, (root, policy, content) in enumerate(zip(nodes, policies, payloads)):
        directory = root / "mvp"
        file = directory / "probe.bin"
        prefix = f"modea_node_{i}"

        assert _request(
            policy,
            FsMkdirEnvelope(request_id=prefix + "_mkdir_01", profile=PROFILE, path=str(directory)),
        ) == (0, b"", "")
        assert directory.is_dir()

        assert _request(
            policy,
            FsWriteEnvelope(
                request_id=prefix + "_write_02",
                profile=PROFILE,
                path=str(file),
                content_length=len(content),
            ),
            content,
        ) == (0, b"", "")
        assert file.read_bytes() == content

        status, result, error = _request(
            policy,
            FsStatEnvelope(request_id=prefix + "_stat_03", profile=PROFILE, path=str(file)),
        )
        assert status == 0 and error == ""
        fields = json.loads(result)
        assert fields["kind"] == "regular" and fields["size"] == len(content)

        assert _request(
            policy,
            FsReadEnvelope(
                request_id=prefix + "_read_04",
                profile=PROFILE,
                path=str(file),
                max_bytes=4096,
            ),
        ) == (0, content, "")

        # Create-only must not overwrite an already committed file.
        status, _, error = _request(
            policy,
            FsWriteEnvelope(
                request_id=prefix + "_repeat_05",
                profile=PROFILE,
                path=str(file),
                content_length=4,
            ),
            b"evil",
        )
        assert status == EX_UNAVAILABLE
        assert "operation failed" in error
        assert file.read_bytes() == content

    # Nodes have disjoint policy roots: a request for node02's physical path
    # over node01's policy must be denied before any filesystem operation.
    foreign = nodes[1] / "mvp" / "probe.bin"
    status, _, error = _request(
        policies[0],
        FsReadEnvelope(
            request_id="modea_cross_node_06",
            profile=PROFILE,
            path=str(foreign),
            max_bytes=4096,
        ),
    )
    assert status == EX_NOPERM and "denied" in error
    assert foreign.read_bytes() == payloads[1]

    status, _, _ = _request(
        policies[0],
        ExecEnvelope(
            request_id="modea_exec_refused_07",
            profile=PROFILE,
            executable="/usr/bin/true",
            argv=(),
            limits=ExecutionLimits(timeout_seconds=1, max_output_bytes=128, max_stdin_bytes=0),
        ),
    )
    assert status in (EX_NOPERM, EX_UNAVAILABLE)
