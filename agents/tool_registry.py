"""Bounded agent tools: validate calls and record outcomes without logging inputs."""
from dataclasses import dataclass
import re
import time


class ToolValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Tool:
    name: str
    role: str
    handler: object
    validate: object
    validate_result: object


@dataclass(frozen=True)
class ToolResult:
    value: object = None
    error_type: str = ""

    @property
    def ok(self):
        return not self.error_type


class ToolRegistry:
    """Only registered Python handlers execute; model/user text cannot name code."""
    def __init__(self):
        self._tools = {}

    def register(self, name, *, role, handler, validate, validate_result):
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_.]{0,63}", name):
            raise ToolValidationError("Invalid tool name")
        if name in self._tools:
            raise ToolValidationError("Duplicate tool")
        if not isinstance(role, str) or not role or not all(callable(f) for f in (handler, validate, validate_result)):
            raise ToolValidationError("Invalid tool registration")
        self._tools[name] = Tool(name, role, handler, validate, validate_result)

    def catalog(self):
        return [{"name": t.name, "role": t.role} for t in self._tools.values()]

    def execute(self, name, arguments, trace):
        start = time.perf_counter()
        tool = self._tools.get(name) if isinstance(name, str) else None
        event = {"tool": name if isinstance(name, str) else "invalid", "role": tool.role if tool else "unknown"}
        value, error = None, ""
        try:
            if tool is None or not isinstance(arguments, dict):
                raise ToolValidationError("Unknown tool or invalid arguments")
            tool.validate(arguments)
            value = tool.handler(**arguments)
            tool.validate_result(value)
        except Exception as exc:
            # Network/model errors can contain authenticated URLs. Store only their type.
            value, error = None, type(exc).__name__
        event.update(status="error" if error else "ok", duration_ms=round((time.perf_counter() - start) * 1000, 3))
        if error:
            event["error_type"] = error
        trace.setdefault("calls", []).append(event)
        return ToolResult(value, error)


def validate_keys(arguments, required, optional=()):
    if set(arguments) - set(required) - set(optional) or not set(required) <= set(arguments):
        raise ToolValidationError("Tool arguments do not match schema")


def validate_records(arguments):
    validate_keys(arguments, {"records"})
    rows = arguments["records"]
    if not isinstance(rows, list) or not rows or len(rows) > 1000 or any(
        not isinstance(row, dict) or not isinstance(row.get("item"), dict)
        or not isinstance(row["item"].get("cve_id"), str) or not row["item"]["cve_id"] for row in rows
    ):
        raise ToolValidationError("Invalid record batch")


def validate_mapping(value):
    if not isinstance(value, dict):
        raise ToolValidationError("Tool result must be an object")


def validate_papers(arguments):
    validate_keys(arguments, {"cve_ids"})
    ids = arguments["cve_ids"]
    if not isinstance(ids, list) or not ids or len(ids) > 1000 or any(
        not isinstance(cve, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve) for cve in ids
    ):
        raise ToolValidationError("Invalid CVE identifiers")


def validate_paper_result(value):
    if not isinstance(value, tuple) or len(value) != 2 or not isinstance(value[0], dict):
        raise ToolValidationError("Invalid paper result")
    if value[1] is not None and not isinstance(value[1], str):
        raise ToolValidationError("Invalid paper error")
    if any(not isinstance(rows, list) for rows in value[0].values()):
        raise ToolValidationError("Invalid paper rows")
