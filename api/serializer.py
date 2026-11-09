from dataclasses import fields, is_dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any


def to_jsonable(value: Any, seen: set[int] | None = None):
    if seen is None:
        seen = set()

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, (Path, Decimal)):
        return str(value)

    if isinstance(value, bytes):
        return value.hex()

    object_id = id(value)

    if object_id in seen:
        raise ValueError("Circular reference detected while serializing an investigation.")

    seen.add(object_id)

    try:
        if is_dataclass(value) and not isinstance(value, type):
            return {item.name: to_jsonable(getattr(value, item.name), seen) for item in fields(value)}

        if hasattr(value, "model_dump"):
            return to_jsonable(value.model_dump(mode="python"), seen)

        if isinstance(value, dict):
            return {str(key): to_jsonable(item, seen) for key, item in value.items()}

        if isinstance(value, (list, tuple, set, frozenset)):
            return [to_jsonable(item, seen) for item in value]

        if hasattr(value, "__dict__"):
            return {key: to_jsonable(item, seen) for key, item in vars(value).items() if not key.startswith("_")}

        slots = getattr(type(value), "__slots__", ())
        if isinstance(slots, str):
            slots = (slots,)

        if slots:
            return {key: to_jsonable(getattr(value, key), seen) for key in slots if hasattr(value, key) and not key.startswith("_")}

        raise TypeError(f"Unsupported value during JSON serialization: {type(value).__name__}")

    finally:
        seen.remove(object_id)
