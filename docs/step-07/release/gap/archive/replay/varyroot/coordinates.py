"""Align the registered CodeQL C/C++ expression inventory to source byte spans."""
from collections import defaultdict
from hashlib import sha256
import re


def physical_span(raw: bytes, start_line, start_column, end_line, end_column):
    """Convert inclusive 1-based scalar columns to a half-open raw UTF-8 byte span."""
    if not isinstance(raw, bytes):
        raise ValueError("source must be raw bytes")
    points = (start_line, start_column, end_line, end_column)
    if any(type(value) is not int or value < 1 for value in points):
        raise ValueError("coordinates must be positive integers")
    if (end_line, end_column) < (start_line, start_column):
        raise ValueError("reversed location")
    lines = re.split(b"(\r\n|\r|\n)", raw)

    def offset(line, col, include):
        index = 2 * (line - 1)
        if index >= len(lines):
            raise ValueError("line outside source")
        content = lines[index].decode("utf-8")
        if col > len(content):
            raise ValueError("column outside source")
        return sum(map(len, lines[:index])) + len(content[:col - 1 + include].encode("utf-8"))

    return [offset(start_line, start_column, 0), offset(end_line, end_column, 1)]


# Pin the ten call-bearing units admitted by Step 07 C1. The regression verifies
# this set against registered_sources(); replay requires only the frozen snapshot.
REGISTERED_CALL_DIGESTS = frozenset("""
28b239cc9a6b83f33a4e7d2055c77d82760f7f0435a6e688dd937c4795092aa0
30b6b82bd06f02a829b085d2a6d498deeb6398e504530f46114723328db91016
60989fe114e23bae1277342a9052ce4a716debc1177182c0186e225a6032e29a
93b7f5b7e9f686e51dd3c7c389a43360343f20a21b021dde2f89d70de1ba964a
a241fecc940fd324a8099a199e2c8e328b891cb7a850a077733db2e472ffa4fd
a86ca48c1d62ce8ef0741cc68d7948aa44dc2221fcd1e2155a58e49aa95af7d7
adfcf4f0dd0855831d2a1132b83224fce415be33d434ce39912334434bbe5bed
cc1639a94a804417c53e6347cf67ad9bded743474195af05fb5c967d401f4a36
cf620cd1074e3aa1cc5e7115a98eb65b65a0871d8e609635b9165872d0cb54e9
fc52d014da3370c5ff1fea8d96e4dbc08d028501b03f44dbaa7f844a3fae453c
""".split())
_CALL = re.compile(rb"^    return (read_required\(p\)|read_span\(data, i, [48]\));$", re.MULTILINE)


def registered_call_span(raw, byte_span):
    """Expand exactly a registered call's callee token using only bound source bytes."""
    if sha256(raw).hexdigest() not in REGISTERED_CALL_DIGESTS:
        raise ValueError("call expansion requires a registered snapshot")
    matches = list(_CALL.finditer(raw))
    if len(matches) != 1:
        raise ValueError("expected one registered return call")
    call, = matches
    start, stop = call.span(1)
    callee = call[1].split(b"(", 1)[0]
    if list(byte_span) != [start, start + len(callee)]:
        raise ValueError("backend location must equal the complete callee token")
    return [start, stop], "registered_return_call_v1/" + callee.decode("ascii")


def _unit(record):
    return (record["snapshot_ref"], record["variant_id"], record["file"])


def _context_matches(target, row):
    macro = target.get("origin_trace", {}).get("replacement_use_span")
    return (("replacement_use_span" not in row or row["replacement_use_span"] == macro)
            and ("callsite_ref" not in row or row["callsite_ref"] == target.get("callsite_ref")))


def align_locations(targets, locations, sources, *, complete=True):
    """Match site/alert/gap rows. Only a complete and uniquely inventoried site is measurable.

    Each source key is (snapshot_ref, variant_id, file); targets carry Step 04 identity.
    An optional multiplicity records distinct backend expressions projected to one row.
    """
    targets = list(targets)
    groups, seen = defaultdict(list), defaultdict(set)
    diagnostics, transformations, by_target = [], [], {}
    ambiguous, invalid = set(), set()
    digests = {key: sha256(raw).hexdigest() for key, raw in sources.items()}
    for target in targets:
        ref = target["target_ref"]
        if ref in by_target:
            raise ValueError("duplicate target_ref")
        by_target[ref] = dict(mapping_status="unmapped", actual_output=None, backend_gap=False)
        unit = _unit(target)
        span = target.get("byte_span", target.get("expr_span"))
        if (unit not in digests or target["file_digest"] != digests[unit]
                or not isinstance(span, (tuple, list)) or len(span) != 2
                or any(type(x) is not int for x in span)
                or not 0 <= span[0] < span[1] <= len(sources[unit])):
            invalid.add(ref)
            diagnostics.append(dict(code="invalid_source_binding", target_ref=ref))
            continue
        groups[unit, tuple(span), target["operation"]].append(target)

    for ordinal, row in enumerate(locations):
        unit = None
        try:
            unit = _unit(row)
            role = row["operation"]
            if row["kind"] not in ("site", "alert", "gap"):
                raise ValueError("unknown row kind")
            if row.get("file_digest", digests[unit]) != digests[unit]:
                raise ValueError("source digest mismatch")
            span = physical_span(sources[unit], row["start_line"], row["start_column"],
                                 row["end_line"], row["end_column"])
            if row.get("registered_call") is True:
                raw_span = span
                span, basis = registered_call_span(sources[unit], raw_span)
                transformations.append(dict(row=ordinal, kind=row["kind"], snapshot_ref=unit[0],
                    variant_id=unit[1], file=unit[2], file_digest=digests[unit], basis=basis,
                    coordinates=[row[k] for k in ("start_line", "start_column", "end_line", "end_column")],
                    raw_byte_span=raw_span, byte_span=span))
            count = row.get("multiplicity", 1)
            if type(count) is not int or count < 1:
                raise ValueError("invalid expression multiplicity")
        except (ValueError, KeyError) as exc:
            diagnostics.append(dict(code="invalid_location", row=ordinal, reason=str(exc)))
            invalid.update(t["target_ref"] for t in targets if unit is None or _unit(t) == unit)
            continue
        group = groups.get((unit, tuple(span), role), [])
        candidates = [t for t in group if _context_matches(t, row)]
        if not candidates:
            diagnostics.append(dict(code="unmatched_location", row=ordinal, byte_span=span))
            # A coarse alert covering targets cannot justify an observed negative for them.
            if row["kind"] in ("alert", "gap"):
                for (key, interval, _), neighbors in groups.items():
                    if key == unit and span[0] < interval[1] and interval[0] < span[1]:
                        ambiguous.update(t["target_ref"] for t in neighbors)
            continue
        if len(candidates) != 1 or count != 1:
            ambiguous.update(t["target_ref"] for t in candidates)
            continue
        target, = candidates
        if target.get("callsite_ref") and not row.get("callsite_ref"):
            ambiguous.add(target["target_ref"])
            continue
        seen[target["target_ref"]].add(row["kind"])

    for group in groups.values():
        for target in group:
            ref = target["target_ref"]
            output = by_target[ref]
            if ref in ambiguous or (len(group) > 1 and "site" not in seen[ref]):
                output["mapping_status"] = "ambiguous"
            elif "site" in seen[ref]:
                output.update(mapping_status="exact_1to1", actual_output="alert" in seen[ref],
                              backend_gap="gap" in seen[ref])
    for ref, output in by_target.items():
        if not complete or ref in invalid:
            output.update(mapping_status="unavailable", actual_output=None, backend_gap=False)
    return dict(by_target=by_target, diagnostics=diagnostics, transformations=transformations)
