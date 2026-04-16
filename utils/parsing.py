from __future__ import annotations

from collections.abc import Iterable
from typing import Any


TERMINAL_STATES = {
    "done",
    "completed",
    "complete",
    "finished",
    "cancelled",
    "canceled",
    "failed",
    "error",
}


def safe_get(payload: dict[str, Any], *path: str, default: Any = None) -> Any:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def extract_search_id(response: dict[str, Any]) -> str | None:
    candidates = [
        safe_get(response, "resources", "id"),
        safe_get(response, "body", "id"),
        safe_get(response, "body", "resources", 0),
    ]
    for item in candidates:
        if isinstance(item, str) and item:
            return item
    return _find_first_value(response, target_keys={"id", "search_id"}, only_strings=True)


def extract_status_text(response: dict[str, Any]) -> str:
    for value in (
        safe_get(response, "body", "state"),
        safe_get(response, "resources", "state"),
        safe_get(response, "body", "status"),
        safe_get(response, "resources", "status"),
        _find_first_value(response, target_keys={"state", "status"}, only_strings=True),
    ):
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "UNKNOWN"


def is_terminal_status(status_text: str) -> bool:
    normalized = status_text.strip().lower()
    return normalized in TERMINAL_STATES


def extract_rows(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Best-effort extraction of tabular rows from NGSIEM responses."""
    candidate_paths = [
        ("body", "events"),
        ("body", "results"),
        ("body", "data"),
        ("resources", "events"),
        ("resources", "results"),
        ("resources", "data"),
        ("events",),
        ("results",),
        ("data",),
    ]
    for path in candidate_paths:
        value = _safe_walk(response, path)
        if _is_row_list(value):
            return [flatten_dict(row) for row in value]

    lists = _find_row_lists(response)
    if lists:
        best = max(lists, key=len)
        return [flatten_dict(row) for row in best]
    return []


def flatten_dict(item: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    for key, value in item.items():
        new_key = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            flattened.update(flatten_dict(value, prefix=new_key))
        elif isinstance(value, list):
            flattened[new_key] = _stringify_list(value)
        else:
            flattened[new_key] = value
    return flattened


def response_error_text(response: dict[str, Any]) -> str:
    errors = response.get("errors")
    if isinstance(errors, list) and errors:
        messages: list[str] = []
        for err in errors:
            if isinstance(err, dict):
                code = err.get("code", "")
                msg = err.get("message", "")
                combined = f"{code}: {msg}".strip(": ")
                if combined:
                    messages.append(combined)
            else:
                messages.append(str(err))
        return " | ".join(messages)
    return "Unknown Falcon API error"


def pick_columns(rows: list[dict[str, Any]], limit: int = 10) -> list[str]:
    priority = [
        "LastSeen",
        "FirstSeen",
        "ComputerName",
        "UserName",
        "ContextBaseFileName",
        "ParentBaseFileName",
        "FileName",
        "Verdict",
        "Severity",
        "Reason",
        "Hits",
        "CommandLine",
        "SampleDecodedCmd",
        "SampleDomains",
        "SampleRemotes",
    ]
    seen: list[str] = []
    all_keys: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in all_keys:
                all_keys.append(key)

    for key in priority:
        if key in all_keys and key not in seen:
            seen.append(key)
    for key in all_keys:
        if key not in seen:
            seen.append(key)
    return seen[:limit]


def _safe_walk(obj: Any, path: Iterable[str]) -> Any:
    current = obj
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _is_row_list(value: Any) -> bool:
    return isinstance(value, list) and value and all(isinstance(item, dict) for item in value)


def _find_row_lists(value: Any) -> list[list[dict[str, Any]]]:
    found: list[list[dict[str, Any]]] = []
    if _is_row_list(value):
        found.append(value)
    elif isinstance(value, dict):
        for child in value.values():
            found.extend(_find_row_lists(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_find_row_lists(child))
    return found


def _find_first_value(value: Any, target_keys: set[str], only_strings: bool = False) -> Any:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in target_keys:
                if not only_strings or isinstance(child, str):
                    return child
            result = _find_first_value(child, target_keys, only_strings=only_strings)
            if result is not None:
                return result
    elif isinstance(value, list):
        for child in value:
            result = _find_first_value(child, target_keys, only_strings=only_strings)
            if result is not None:
                return result
    return None


def _stringify_list(values: list[Any]) -> str:
    parts: list[str] = []
    for item in values:
        if isinstance(item, dict):
            parts.append(str(flatten_dict(item)))
        else:
            parts.append(str(item))
    return " | ".join(parts)
