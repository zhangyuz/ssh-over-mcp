from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .models import ConfigBundle


class ConfigError(ValueError):
    pass


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: yaml.Loader, node: yaml.nodes.MappingNode, deep: bool = False) -> dict:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ConfigError(f"duplicate configuration key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def loads_config(data: str, *, format: str = "yaml") -> ConfigBundle:
    try:
        if format == "yaml":
            raw = yaml.load(data, Loader=_UniqueKeyLoader)
        elif format == "json":
            raw = json.loads(data)
        else:
            raise ConfigError(f"unsupported configuration format: {format}")
        if not isinstance(raw, dict):
            raise ConfigError("configuration root must be a mapping")
        return ConfigBundle.model_validate(raw)
    except ConfigError:
        raise
    except (yaml.YAMLError, json.JSONDecodeError, ValidationError) as exc:
        raise ConfigError(str(exc)) from exc


def load_config(path: str | Path) -> ConfigBundle:
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        fmt = "yaml"
    elif suffix == ".json":
        fmt = "json"
    else:
        raise ConfigError(f"unsupported configuration file extension: {suffix}")
    return loads_config(path.read_text(encoding="utf-8"), format=fmt)
