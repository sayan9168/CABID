"""A small, strict query language over normalized CABID events.

`jq` answers "what is in this file" only if you already know the schema and are
comfortable writing filters. Hunt answers the question an analyst actually asks
during triage: *which events mention cron, or touched /etc, in this window?* —
with the referenced fields checked against the schema before anything runs.

The grammar is deliberately tiny:

    query      := or_expr
    or_expr    := and_expr ( "or" and_expr )*
    and_expr   := unary ( "and" unary )*
    unary      := "not" unary | "(" query ")" | comparison
    comparison := field op value
                | field "in" "[" value ("," value)* "]"
                | field "contains" value
    op         := "=" | "!=" | ">" | ">=" | "<" | "<=" | "~" | "!~"

`~` and `!~` are case-sensitive glob matches (``/etc/*``, ``*.sh``). ``and``,
``or``, ``not``, and ``in`` are case-insensitive keywords; everything else is
literal.

Honesty notes that shape the implementation:

* An unknown field is a parse error with a suggestion, not a silently empty
  result. A typo that matches nothing looks exactly like "no evidence".
* A missing field never satisfies ``=``, ``~``, ``contains``, ``in``, or an
  ordering comparison, and *does* satisfy ``!=`` and ``!~``. The per-field
  presence counts in the result make that behaviour visible instead of implied.
* Matching is deterministic: input order is preserved, and group rollups sort by
  count descending then value ascending.
"""
from __future__ import annotations

import fnmatch
import re

FORMAT = "cabid-hunt/1"

NUMERIC_FIELDS = {"timestamp", "process_id", "parent_process_id", "pid_ns"}
STRING_FIELDS = {
    "timestamp_iso", "event_type", "process_name", "executable", "target",
    "source", "event_id", "container_id", "container",
}
FIELDS = NUMERIC_FIELDS | STRING_FIELDS
ALIASES = {
    "pid": "process_id",
    "ppid": "parent_process_id",
    "ts": "timestamp",
    "time": "timestamp",
    "type": "event_type",
    "name": "process_name",
    "comm": "process_name",
    "exe": "executable",
    "path": "target",
}
KEYWORDS = {"and", "or", "not", "in", "contains"}
NUMERIC_OPS = {"=", "!=", ">", ">=", "<", "<="}
GLOB_OPS = {"~", "!~"}
ORDERING_OPS = {">", ">=", "<", "<="}

_TOKEN_RE = re.compile(
    r"""
      (?P<space>\s+)
    | (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
    | (?P<op>!~|>=|<=|!=|=|~|>|<)
    | (?P<punct>[(),\[\]])
    | (?P<word>[^\s(),\[\]"'=!~<>]+)
    """,
    re.VERBOSE,
)
_NUMBER_RE = re.compile(r"^-?\d+(?:\.\d+)?$")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'"}


class HuntError(ValueError):
    """Raised when a hunt query cannot be parsed or references unknown fields."""


def _suggest(name: str) -> str:
    import difflib

    choices = sorted(FIELDS | set(ALIASES))
    close = difflib.get_close_matches(name, choices, n=3, cutoff=0.6)
    if close:
        return f"; did you mean {', '.join(close)}?"
    return f"; known fields: {', '.join(sorted(FIELDS))}"


def resolve_field(name: str) -> str:
    """Map an alias to a schema field, raising HuntError when unknown."""
    key = str(name).strip().lower()
    if key in ALIASES:
        key = ALIASES[key]
    if key not in FIELDS:
        raise HuntError(f"unknown field: {name}{_suggest(key)}")
    return key


def _unescape(text: str) -> str:
    out, index = [], 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            nxt = text[index + 1]
            out.append(_ESCAPES.get(nxt, "\\" + nxt))
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _tokenize(query: str) -> list[tuple[str, str, int]]:
    tokens: list[tuple[str, str, int]] = []
    position = 0
    while position < len(query):
        match = _TOKEN_RE.match(query, position)
        if match is None:
            raise HuntError(f"unexpected character {query[position]!r} at column {position + 1}")
        kind = match.lastgroup or ""
        text = match.group()
        if kind == "string":
            tokens.append(("string", _unescape(text[1:-1]), position))
        elif kind != "space":
            tokens.append((kind, text, position))
        position = match.end()
    tokens.append(("end", "", len(query)))
    return tokens


def _check_value_type(field: str, value: object, op: str) -> None:
    """Reject comparisons that can only ever return False."""
    if field in NUMERIC_FIELDS and op in ORDERING_OPS and not isinstance(value, float):
        raise HuntError(f"{field} is numeric; '{op}' needs a number, not {value!r}")
    if field in STRING_FIELDS and op in ORDERING_OPS:
        raise HuntError(f"{field} is a string field; '{op}' is only defined for numeric fields")


class _Parser:
    def __init__(self, query: str):
        self.query = query
        self.tokens = _tokenize(query)
        self.index = 0
        self.fields: set[str] = set()
        self.operators: set[str] = set()

    # -- token helpers -----------------------------------------------------
    def peek(self) -> tuple[str, str, int]:
        return self.tokens[self.index]

    def next(self) -> tuple[str, str, int]:
        token = self.tokens[self.index]
        self.index += 1
        return token

    def at_keyword(self, *words: str) -> bool:
        kind, text, _ = self.peek()
        return kind == "word" and text.lower() in words

    def expect(self, kind: str, text: str | None = None) -> tuple[str, str, int]:
        token = self.next()
        if token[0] != kind or (text is not None and token[1] != text):
            found = token[1] or "end of query"
            wanted = text or kind
            raise HuntError(f"expected {wanted} at column {token[2] + 1}, found {found!r}")
        return token

    # -- grammar -----------------------------------------------------------
    def parse(self) -> tuple:
        if not self.query.strip():
            raise HuntError("query is empty")
        node = self.parse_or()
        kind, text, position = self.peek()
        if kind != "end":
            raise HuntError(f"unexpected {text!r} at column {position + 1}")
        return node

    def parse_or(self) -> tuple:
        node = self.parse_and()
        while self.at_keyword("or"):
            self.next()
            node = ("or", (node, self.parse_and()))
        return node

    def parse_and(self) -> tuple:
        node = self.parse_unary()
        while self.at_keyword("and"):
            self.next()
            node = ("and", (node, self.parse_unary()))
        return node

    def parse_unary(self) -> tuple:
        if self.at_keyword("not"):
            self.next()
            return ("not", self.parse_unary())
        kind, text, _ = self.peek()
        if kind == "punct" and text == "(":
            # A parenthesised value list can never start an expression, so this is
            # unambiguously grouping.
            self.next()
            node = self.parse_or()
            self.expect("punct", ")")
            return node
        return self.parse_comparison()

    def parse_comparison(self) -> tuple:
        kind, text, position = self.next()
        if kind != "word" or text.lower() in KEYWORDS:
            raise HuntError(f"expected a field name at column {position + 1}, found {text!r}")
        field = resolve_field(text)
        self.fields.add(field)
        operator = self.next()
        if operator[0] == "op":
            value = self.parse_value(field, operator[1])
            self.operators.add(operator[1])
            return ("cmp", field, operator[1], value)
        if operator[0] == "word" and operator[1].lower() in {"in", "contains"}:
            word = operator[1].lower()
            self.operators.add(word)
            if word == "contains":
                if field in NUMERIC_FIELDS:
                    raise HuntError(f"'contains' is not defined for numeric field {field}")
                return ("contains", field, self.parse_value(field, "contains"))
            return ("in", field, self.parse_list(field))
        found = operator[1] or "end of query"
        raise HuntError(f"expected an operator after {field} at column {operator[2] + 1}, "
                        f"found {found!r}")

    def parse_list(self, field: str) -> tuple:
        self.expect("punct", "[")
        values = []
        if not (self.peek()[0] == "punct" and self.peek()[1] == "]"):
            values.append(self.parse_value(field, "in"))
            while self.peek()[0] == "punct" and self.peek()[1] == ",":
                self.next()
                values.append(self.parse_value(field, "in"))
        self.expect("punct", "]")
        if not values:
            raise HuntError("'in' needs at least one value")
        return tuple(values)

    def parse_value(self, field: str, op: str) -> object:
        kind, text, position = self.next()
        if kind == "string":
            value: object = text
        elif kind == "word":
            value = float(text) if _NUMBER_RE.match(text) else text
        else:
            found = text or "end of query"
            raise HuntError(f"expected a value at column {position + 1}, found {found!r}")
        if field in NUMERIC_FIELDS:
            if isinstance(value, str) and _NUMBER_RE.match(value.strip()):
                value = float(value)
            elif not isinstance(value, float):
                raise HuntError(f"{field} is numeric; {value!r} is not a number")
        elif isinstance(value, float):
            # A numeric literal against a string field means the text the analyst
            # typed: `target = 443` should match the string "443", not nothing.
            value = text
        _check_value_type(field, value, op)
        return value


def parse_query(query: str) -> tuple:
    """Parse a query into an AST, validating fields and operator types."""
    if not isinstance(query, str):
        raise HuntError("query must be a string")
    return _Parser(query).parse()


def describe_query(query: str) -> dict:
    """The query's shape, without running it. Used in the result receipt."""
    parser = _Parser(query)
    parser.parse()
    return {
        "fields": sorted(parser.fields),
        "operators": sorted(parser.operators),
        "uses_negation": "not" in query.lower().split() or "!=" in parser.operators
        or "!~" in parser.operators,
    }


def _compare(field: str, op: str, expected: object, event: dict) -> bool:
    actual = event.get(field)
    if actual is None:
        # Absence is not equality; it is only a kind of inequality.
        return op in {"!=", "!~"}
    numeric = field in NUMERIC_FIELDS
    number = 0.0
    text = ""
    if numeric:
        try:
            number = float(actual)
        except (TypeError, ValueError):
            return False
    else:
        text = str(actual)
    if op in ORDERING_OPS:
        right_number = float(str(expected))
        if op == ">":
            return number > right_number
        if op == ">=":
            return number >= right_number
        if op == "<":
            return number < right_number
        return number <= right_number
    if numeric:
        right_number = float(str(expected))
        if op == "=":
            return number == right_number
        if op == "!=":
            return number != right_number
        return False
    right_text = str(expected)
    if op == "=":
        return text == right_text
    if op == "!=":
        return text != right_text
    if op == "~":
        return fnmatch.fnmatchcase(text, right_text)
    if op == "!~":
        return not fnmatch.fnmatchcase(text, right_text)
    return False


def matches(node: tuple, event: dict) -> bool:
    """Evaluate a parsed query against one normalized event."""
    kind = node[0]
    if kind == "cmp":
        return _compare(node[1], node[2], node[3], event)
    if kind == "in":
        return any(_compare(node[1], "=", value, event) for value in node[2])
    if kind == "contains":
        actual = event.get(node[1])
        return actual is not None and str(node[2]) in str(actual)
    if kind == "not":
        return not matches(node[1], event)
    if kind == "and":
        return all(matches(child, event) for child in node[1])
    if kind == "or":
        return any(matches(child, event) for child in node[1])
    raise HuntError(f"unknown query node: {kind}")


def _field_presence(events: list[dict], fields: set[str]) -> dict:
    presence = {}
    for field in sorted(fields):
        present = sum(1 for event in events if event.get(field) not in (None, ""))
        presence[field] = {"present": present, "missing": len(events) - present}
    return presence


def _group(events: list[dict], field: str) -> list[dict]:
    counts: dict[str, int] = {}
    for event in events:
        raw = event.get(field)
        key = "" if raw is None else str(raw)
        counts[key] = counts.get(key, 0) + 1
    rows = [{"value": key, "count": count} for key, count in counts.items()]
    rows.sort(key=lambda row: (-int(str(row["count"])), str(row["value"])))
    return rows


def run_query(events: list[dict], query: str, *, group_by: str | None = None,
              limit: int = 50, include_events: bool = True) -> dict:
    """Run a query over normalized events and return a receipt plus matches.

    ``limit`` bounds only the returned event list; every count in the result
    describes the full match set. A non-positive ``limit`` disables the bound.
    """
    if not isinstance(events, list):
        raise HuntError("events must be a list of normalized event dicts")
    node = parse_query(query)
    described = describe_query(query)
    group_field = resolve_field(group_by) if group_by else None
    matched: list[dict] = []
    type_counts: dict[str, int] = {}
    for event in events:
        if not isinstance(event, dict):
            raise HuntError("events must be dictionaries; use cabid.ingest.read_jsonl")
        if matches(node, event):
            matched.append(event)
            name = str(event.get("event_type", "unknown"))
            type_counts[name] = type_counts.get(name, 0) + 1
    process_counts: dict[str, int] = {}
    for event in matched:
        name = str(event.get("process_name") or "unknown")
        process_counts[name] = process_counts.get(name, 0) + 1
    top = sorted(process_counts.items(), key=lambda item: (-item[1], item[0]))[:5]
    timestamps = [float(event["timestamp"]) for event in matched if "timestamp" in event]
    returned = matched if limit <= 0 else matched[:limit]
    result = {
        "format": FORMAT,
        "query": query,
        "parsed": described,
        "events_scanned": len(events),
        "events_matched": len(matched),
        "match_ratio": round(len(matched) / len(events), 6) if events else 0.0,
        "field_presence": _field_presence(events, set(described["fields"])),
        "event_type_counts": dict(sorted(type_counts.items())),
        "top_processes": [{"process_name": name, "count": count} for name, count in top],
        "first_match_timestamp": round(min(timestamps), 6) if timestamps else None,
        "last_match_timestamp": round(max(timestamps), 6) if timestamps else None,
        "group_by": group_field,
        "groups": _group(matched, group_field) if group_field else [],
        "returned": len(returned),
        "truncated": len(returned) < len(matched),
        "events": returned if include_events else [],
        "semantics": "a match reports that an event satisfies the query; it is not a verdict",
    }
    result["notes"] = _notes(result)
    return result


def _notes(result: dict) -> list[str]:
    notes = []
    if result["events_scanned"] == 0:
        notes.append("no events were supplied, so the query proves nothing either way")
    if result["truncated"]:
        notes.append(f"only {result['returned']} of {result['events_matched']} matches are "
                     "listed; counts describe the full match set")
    for field, counts in result["field_presence"].items():
        if counts["present"] == 0 and result["events_scanned"]:
            notes.append(f"field {field!r} is absent from every event; comparisons on it "
                         "can only satisfy '!=' or '!~'")
    return notes


def render_table(result: dict, fields: list[str] | None = None) -> str:
    """Fixed-width table of the returned events, plus the receipt header."""
    columns = fields or ["timestamp", "event_type", "process_id", "process_name",
                         "executable", "target"]
    lines = [
        f"query: {result['query']}",
        f"matched {result['events_matched']} of {result['events_scanned']} events"
        + (f" (showing {result['returned']})" if result["truncated"] else ""),
    ]
    if result["group_by"]:
        lines.append(f"grouped by {result['group_by']}:")
        for row in result["groups"][:20]:
            lines.append(f"  {row['count']:>6}  {row['value'] or '(empty)'}")
    if not result["events"]:
        if result["events_matched"] == 0:
            lines.append("")
            lines.append("no matching events")
        return "\n".join(lines) + "\n"
    lines.append("")
    widths = []
    for column in columns:
        header = column
        widest = max([len(header)] + [len(_cell(event.get(column))) for event in result["events"]])
        widths.append(min(widest, 40))
    lines.append("  ".join(column[:width].ljust(width)
                           for column, width in zip(columns, widths)))
    lines.append("  ".join("-" * width for width in widths))
    for event in result["events"]:
        lines.append("  ".join(_cell(event.get(column))[:width].ljust(width)
                               for column, width in zip(columns, widths)).rstrip())
    return "\n".join(lines) + "\n"


def _cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".")
    return str(value)


__all__ = ["FORMAT", "FIELDS", "NUMERIC_FIELDS", "STRING_FIELDS", "ALIASES",
           "HuntError", "parse_query", "describe_query", "matches", "resolve_field",
           "run_query", "render_table"]
