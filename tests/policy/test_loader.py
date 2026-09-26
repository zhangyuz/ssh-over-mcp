import pytest

from ssh_over_mcp.config.loader import ConfigError, loads_config


def test_duplicate_yaml_keys_are_rejected():
    data = """
inventory:
  hosts:
    dev01:
      address: 10.0.0.1
      ssh_user: mcp
      credential_ref: secret://dev
      host_key: key
policy:
  roles:
    developer: {}
    developer: {}
  rules: []
"""
    with pytest.raises(ConfigError, match="duplicate"):
        loads_config(data)


def test_unknown_config_fields_are_rejected():
    data = """
inventory:
  hosts:
    dev01:
      address: 10.0.0.1
      ssh_user: mcp
      credential_ref: secret://dev
      host_key: key
      unexpected: true
policy:
  roles:
    developer: {}
  rules: []
"""
    with pytest.raises(ConfigError):
        loads_config(data)
