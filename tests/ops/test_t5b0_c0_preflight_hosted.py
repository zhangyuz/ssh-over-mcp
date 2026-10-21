"""Include C0 offline fail-closed unittest fixtures in the existing CI rest shard."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_c0_offline_manifest_adversarial_fixtures():
    """Run all offline C0 fixtures on both hosted Python versions without CI changes."""
    subprocess.run(
        [sys.executable, '-m', 'unittest', 'discover', '-s', 'ops/t5b0', '-p', 'test_*.py', '-v'],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
        # This invokes the *entire* 150+ case subprocess/FS C0 suite. A
        # busy hosted Python 3.14 runner can legitimately exceed 45 seconds.
        # Keep a finite whole-suite watchdog; per-input caps remain unchanged.
        timeout=180,
    )
