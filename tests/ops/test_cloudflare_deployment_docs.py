from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_GUIDE = _REPO_ROOT / "docs" / "cloudflare-deployment.md"


def test_phase6c_guide_pins_private_portal_registration_contract() -> None:
    text = _GUIDE.read_text(encoding="utf-8")

    assert "http://<private-hostname>:8000/mcp" in text
    assert "auth_type: bearer" in text
    assert "auth_credentials: <existing origin bearer>" in text
    assert "Route traffic through Cloudflare Gateway" in text


def test_phase6c_guide_separates_connector_and_origin_credentials() -> None:
    text = _GUIDE.read_text(encoding="utf-8")

    assert "Tunnel token" in text
    assert "origin bearer" in text
    assert "Tunnel token is not the origin bearer" in text
    assert "origin bearer is not mounted into `cloudflared`" in text


def test_phase6c_guide_keeps_live_account_mutation_manual() -> None:
    text = _GUIDE.read_text(encoding="utf-8")

    assert "Phase 6C does not mutate your Cloudflare account automatically" in text
    assert "create/select a remotely managed Tunnel manually" in text
    assert "do not create a public-origin DNS record" in text


def test_phase6c_guide_scopes_gateway_to_defense_in_depth() -> None:
    text = _GUIDE.read_text(encoding="utf-8")

    assert "real-time tool call" in text
    assert "Gateway HTTP logs" in text
    assert "application policy, approval, and audit remain authoritative" in text
    assert "background credential/capability synchronization" in text
