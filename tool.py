#!/usr/bin/env python3
"""Bounded offline audit. No network access or external state changes."""
import argparse
import json
import math
import re
import sys
import stat
from pathlib import Path

MAX_BYTES = 262144
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")

class InputError(ValueError):
    pass

class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse messages may contain raw options, paths, or caller secrets.
        raise InputError("invalid command-line arguments")

def require(condition, message):
    if not condition:
        raise InputError(message)

def schema(data, required, optional=()):
    require(isinstance(data, dict), "input must be an object")
    require(set(required) <= data.keys(), "missing required input field")
    require(data.keys() <= set(required) | set(optional), "unknown input field")

def integer(value, minimum=0, maximum=253402300799):
    require(type(value) is int and minimum <= value <= maximum, "integer outside supported range")
    return value

def string(value, limit=8192):
    require(isinstance(value, str) and len(value) <= limit, "string outside supported length")
    require(not any(0xD800 <= ord(c) <= 0xDFFF for c in value), "invalid Unicode scalar")
    return value

def header(value):
    string(value)
    require(not any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in value), "header contains control characters")
    return value

def result(findings, **fields):
    return {"schema_version": 1, "ok": not findings, "findings": findings, **fields}

def issue(code, **extra):
    return {"code": code, **extra}

def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, "duplicate JSON key")
        obj[key] = value
    return obj

def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument("--input", default="-", help="JSON file, or - for stdin (maximum 256 KiB)")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    args = None
    try:
        args = parser.parse_args(argv)
        if args.input == "-":
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            require(stat.S_ISREG(Path(args.input).stat().st_mode), "input path must be a regular file")
            with open(args.input, "rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
        require(len(raw) <= MAX_BYTES, "input exceeds 256 KiB")
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(InputError("non-finite JSON number")))
        out = audit(data)
    except InputError as exc:
        out = {"schema_version": 1, "ok": False, "error": {"code": "invalid_input", "message": str(exc)}}
        code = 2
    except (OSError, UnicodeError, ValueError, RecursionError, OverflowError):
        out = {"schema_version": 1, "ok": False, "error": {"code": "invalid_input", "message": "unreadable, malformed, or excessively nested input"}}
        code = 2
    else:
        code = 0 if out["ok"] else 1
    print(json.dumps(out, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2 if args is not None and args.pretty else None))
    return code

def split_quoted(value, delimiter=","):
    parts, start, quoted, escaped = [], 0, False, False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == delimiter and not quoted:
            parts.append(value[start:index].strip(" \t")); start = index + 1
    require(not quoted and not escaped, "unterminated quoted string")
    parts.append(value[start:].strip(" \t"))
    return parts

def parameter_value(raw):
    if raw.startswith('"'):
        require(len(raw) >= 2 and raw.endswith('"'), "invalid quoted value")
        out, escaped = [], False
        for char in raw[1:-1]:
            if escaped:
                out.append(char); escaped = False
            elif char == "\\":
                escaped = True
            else:
                require(char != '"', "unescaped quote")
                out.append(char)
        require(not escaped, "unterminated quoted escape")
        return "".join(out)
    require(bool(TOKEN.fullmatch(raw)), "invalid token value")
    return raw

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime, format_datetime

def http_date(raw):
    # Deliberately IMF-fixdate only, not an obsolete HTTP-date parser.
    header(raw)
    require(bool(re.fullmatch(r"[A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT", raw)), "expected IMF-fixdate")
    try:
        parsed = parsedate_to_datetime(raw)
        require(format_datetime(parsed, usegmt=True) == raw, "invalid IMF-fixdate or weekday")
        return int(parsed.timestamp())
    except (ValueError, TypeError, OverflowError) as exc:
        raise InputError("invalid IMF-fixdate") from exc

def audit(data):
    schema(data, ("request_time", "response_time", "now", "date", "age", "cache_control"))
    request, response, now = (integer(data[key]) for key in ("request_time", "response_time", "now"))
    require(request <= response <= now, "clock ordering must be request <= response <= now")
    date = http_date(data["date"])
    age_raw = string(data["age"], 20)
    require(bool(re.fullmatch(r"[0-9]+", age_raw)), "Age must be nonnegative ASCII decimal seconds")
    age = int(age_raw)
    require(age <= 2**63-1, "Age outside supported range")
    fields = data["cache_control"]
    require(isinstance(fields, list) and 1 <= len(fields) <= 20, "cache_control must have 1..20 field lines")
    directives = {}
    findings = []
    for field in fields:
        for entry in split_quoted(header(field)):
            require(bool(entry), "empty Cache-Control directive unsupported")
            name, sep, raw = entry.partition("=")
            name = name.strip(" \t").lower()
            require(bool(TOKEN.fullmatch(name)), "invalid Cache-Control directive name")
            value = parameter_value(raw.strip(" \t")) if sep else None
            directives.setdefault(name, []).append(value)
    maximums = directives.get("max-age", [])
    maximum = None
    if len(maximums) != 1:
        findings.append(issue("missing_or_duplicate_max_age"))
    elif maximums[0] is None or not re.fullmatch(r"[0-9]+", maximums[0]) or len(maximums[0]) > 19:
        findings.append(issue("invalid_max_age"))
    else:
        maximum = int(maximums[0])
        if maximum > 2**63-1:
            maximum = None; findings.append(issue("max_age_outside_supported_range"))
    apparent = max(0, response - date)
    delay = response - request
    corrected = max(apparent, age + delay)
    current = corrected + now - response
    fresh = maximum is not None and current < maximum
    if maximum is not None and not fresh:
        findings.append(issue("stale_by_max_age"))
    if date > response:
        findings.append(issue("origin_date_ahead_of_receive_clock"))
    policy = sorted(set(directives) & {"no-cache", "no-store", "s-maxage", "private"})
    if policy:
        findings.append(issue("additional_cache_policy_requires_review", directives=policy))
    return result(findings, apparent_age_seconds=apparent, response_delay_seconds=delay,
                  corrected_initial_age_seconds=corrected, resident_time_seconds=now-response,
                  current_age_seconds=current, max_age_seconds=maximum,
                  fresh_by_max_age=fresh, remaining_fresh_seconds=max(0, maximum-current) if maximum is not None else None,
                  unmodeled_directives=sorted(set(directives)-{"max-age"}), reuse_authorized=False)

if __name__ == "__main__":
    raise SystemExit(main())
