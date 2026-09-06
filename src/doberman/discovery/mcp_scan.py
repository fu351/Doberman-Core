"""Static, redaction-safe admission scanning for repository MCP configs."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from doberman.models import Risk
from doberman.tokens import scan_text

MCP_CONFIG_FILES = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".mcp.json",
)

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_TEMPLATE_RE = re.compile(r"\$\{|\{[^{}]+\}")
_PIPE_TO_SHELL_RE = re.compile(
    r"\b(?:curl|wget)\b[^|\r\n]*\|\s*(?:[^\s|]*/)?(?:ba)?sh\b", re.IGNORECASE
)
_OPAQUE_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_ENV_REFERENCE_RE = re.compile(r"\$\{[^{}]+\}")
_SECRET_KEY_RE = re.compile(r"KEY|TOKEN|SECRET|PASSWORD", re.IGNORECASE)
_INVISIBLE_CHANNELS = frozenset(
    {
        "tag_block",
        "bidi_controls",
        "variation_selectors",
        "noncharacter",
        "unpaired_surrogate",
        "invisible_only",
        "zero_width",
        "private_use",
        "control_chars",
    }
)

_RISK_BY_PATTERN = {
    "invisible_chars": Risk.high,
    "mixed_script": Risk.medium,
    "whole_script": Risk.medium,
    "templated_url": Risk.high,
    "raw_ip_url": Risk.high,
    "non_https_url": Risk.medium,
    "pipe_to_shell": Risk.critical,
    "inline_shell_url": Risk.high,
    "opaque_blob": Risk.high,
    "inline_secret_env": Risk.high,
    "unreadable_config": Risk.medium,
}


@dataclass(frozen=True)
class McpFinding:
    """One pattern-only finding; no field contains raw MCP configuration values."""

    server: str
    source_file: str
    category: str
    pattern_class: str
    risk: Risk


def _ascii_safe(value: str) -> str:
    return value.encode("ascii", "backslashreplace").decode("ascii")


def _string_args(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    lowered = host.rstrip(".").lower()
    if lowered == "localhost" or lowered.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(lowered).is_loopback
    except ValueError:
        return False


def _url_pattern_classes(value: str) -> set[str]:
    classes: set[str] = set()
    for match in _URL_RE.finditer(value):
        url = match.group(0)
        if _TEMPLATE_RE.search(url):
            classes.add("templated_url")
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
        except ValueError:
            host = None
        if host:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                classes.add("raw_ip_url")
        if url.lower().startswith("http://") and not _is_loopback(host):
            classes.add("non_https_url")
    return classes


def _finding(server: str, source_file: str, category: str, pattern_class: str) -> McpFinding:
    return McpFinding(
        server=_ascii_safe(server),
        source_file=source_file,
        category=category,
        pattern_class=pattern_class,
        risk=_RISK_BY_PATTERN[pattern_class],
    )


def _scan_server(server: str, source_file: str, config: dict[str, object]) -> set[McpFinding]:
    findings: set[McpFinding] = set()
    command = config.get("command") if isinstance(config.get("command"), str) else ""
    args = _string_args(config.get("args"))

    for text in [server, command, *args]:
        channels = set(scan_text(text).channels())
        if channels & _INVISIBLE_CHANNELS:
            findings.add(_finding(server, source_file, "unicode", "invisible_chars"))
        if "mixed_script_confusable" in channels:
            findings.add(_finding(server, source_file, "unicode", "mixed_script"))
        if "whole_script_confusable" in channels:
            findings.add(_finding(server, source_file, "unicode", "whole_script"))

    env = config.get("env")
    env_values: list[str] = []
    if isinstance(env, dict):
        for key, value in env.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            env_values.append(value)
            if _SECRET_KEY_RE.search(key) and value and not _ENV_REFERENCE_RE.fullmatch(value):
                findings.add(_finding(server, source_file, "secrets", "inline_secret_env"))

    url_values = _string_args(config.get("url")) + args + env_values
    for value in url_values:
        for pattern_class in _url_pattern_classes(value):
            findings.add(_finding(server, source_file, "egress", pattern_class))

    launch = " ".join([command, *args])
    if _PIPE_TO_SHELL_RE.search(launch):
        findings.add(_finding(server, source_file, "launch", "pipe_to_shell"))

    executable = command.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
    if executable in {"bash", "sh"} and "-c" in args:
        shell_payload = " ".join(args[args.index("-c") + 1 :])
        if _URL_RE.search(shell_payload):
            findings.add(_finding(server, source_file, "launch", "inline_shell_url"))

    if any(_OPAQUE_BLOB_RE.fullmatch(arg) for arg in args):
        findings.add(_finding(server, source_file, "launch", "opaque_blob"))
    return findings


def scan_mcp_configs(repo_root: str) -> list[McpFinding]:
    """Read only known repo MCP config files and return deterministic safe findings.

    This function performs no process spawning or network I/O. Unreadable or
    malformed JSON becomes one redacted parse finding instead of escaping.
    """
    root = Path(repo_root)
    findings: set[McpFinding] = set()
    for source_file in MCP_CONFIG_FILES:
        config_path = root.joinpath(*source_file.split("/"))
        try:
            if not config_path.is_file():
                continue
            document = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            findings.add(_finding("<config>", source_file, "parse", "unreadable_config"))
            continue

        if not isinstance(document, dict):
            continue
        servers = document.get("mcpServers")
        if not isinstance(servers, dict):
            continue
        for server, config in servers.items():
            if isinstance(server, str) and isinstance(config, dict):
                findings.update(_scan_server(server, source_file, config))

    return sorted(
        findings,
        key=lambda item: (
            item.source_file,
            item.server,
            item.category,
            item.pattern_class,
            item.risk.value,
        ),
    )
