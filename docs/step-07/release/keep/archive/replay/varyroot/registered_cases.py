"""Predeclared changes to the reviewed toy sources. No target discovery or external inputs."""
from dataclasses import dataclass
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures"
NOTE = b"    /* target remains in the same function */\n"
READ = b"    return read_required(p);"
ARRAY = b"    return data[i];"


@dataclass(frozen=True)
class Proposal:
    name: str
    parent: bytes
    source: bytes
    focus: str
    equivalent: bool
    before: bytes
    after: bytes


def edit(name, parent, focus, before, after, equivalent=False):
    if parent.count(before) != 1:
        raise ValueError("template parent does not contain a unique reviewed site")
    return Proposal(name, parent, parent.replace(before, after), focus, equivalent, before, after)


def proposals(family, repair):
    folder = FIXTURES / ("npd05" if family == "npd" else "agent_a")
    before = (folder / "before.c").read_bytes()
    after = (folder / repair).read_bytes()
    target = READ if family == "npd" else ARRAY
    out = [edit(family + "_note_" + side, raw, "comment", target, NOTE + target, True)
           for side, raw in (("before", before), ("after", after))]
    if family == "npd":
        for name, action in (("observe", b"(void)0"), ("rebind", b"p = &live"), ("exit", b"return 0")):
            out.append(edit("npd_act_" + name, before, "null_branch_action", READ,
                            b"    if (!p) " + action + b";\n" + READ))
    else:
        for i in (0, 1, 2, 4):
            out.append(edit("oob_index_" + str(i), before, "index_initializer", b"i = 3;",
                            ("i = %d;" % i).encode()))
        # physical data[8] is fully allocated; the approved logical prefix is two entries.
        # Both selected widths are whole numbers of elements and the start index is one.
        inside = before.replace(b"i = 3;", b"i = 1;")
        control = edit("oob_span_control", inside, "access_form", ARRAY, b"    return read_span(data, i, 4);", True)
        out.append(control)
        narrow = control.source
        out.append(edit("oob_wide", narrow, "access_width", b"read_span(data, i, 4)", b"read_span(data, i, 8)"))
        out.append(edit("oob_narrow_note", narrow, "comment", b"    return", NOTE + b"    return", True))
    return out


def registry_extensions():
    existing = {(FIXTURES / rel).read_bytes() for rel in (
        "npd05/before.c", "npd05/exit.c", "npd05/rebind.c", "npd05/modes.c", "agent_a/before.c",
        "agent_a/after.c", "agent_a/after_rebound.c")}
    result = {}
    for family, repair in (("npd", "exit.c"), ("npd", "rebind.c"),
                           ("oob", "after_rebound.c"), ("oob", "after.c")):
        for p in proposals(family, repair):
            if p.source not in existing:
                result["oob_narrow" if p.name == "oob_span_control" else p.name + "_" + repair[:-2]] = p.source
                existing.add(p.source)
            if p.focus == "access_width" and p.parent not in existing:
                result["oob_narrow"] = p.parent
                existing.add(p.parent)
    return result
