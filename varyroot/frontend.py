"""Clang source index for the Step 04 reviewed, self-contained translation units."""
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

CLANG = "/usr/bin/clang-18"
VERSION = "Ubuntu clang version 18.1.3 (1ubuntu1)"
TRIPLE = "x86_64-pc-linux-gnu"
ADAPTER = "step04-clang-v1"


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _id(prefix, *fields):
    data = json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return prefix + ":" + _digest(data.encode())


def _registered():
    registry = {"accesses.cpp": {"d42fe295191f4919bac645fb5a299b01d925451677faa023fb1db3d2367637cb"},
                "sample.c": set()}
    for prefix in ["", "/* reviewed skeleton */\n"]:
        for guard in ["", "    if (i >= 2) return 0;\n", "    if (i >= 2) i = 1;\n"]:
            unit = (prefix + "unsigned sample(void) {\n    unsigned data[8] = {0};\n"
                    + "    unsigned i = 3;\n" + guard + "    return data[i];\n}\n")
            registry["sample.c"].add(_digest(unit.encode()))
    return registry


_BASENAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,80}\.(?:c|cpp)\Z", re.ASCII)
_IDENT = r"[A-Za-z][A-Za-z_0-9]{0,63}"
_NUMBER = r"[0-9]{1,4}"
_VALUE = rf"(?:{_IDENT}|{_NUMBER})"
_ELEMENT = rf"{_IDENT}\s*\[\s*{_VALUE}\s*\]"
_ATOM = rf"(?:{_ELEMENT}|{_VALUE})"
_TYPE = r"(?:unsigned(?:\s+int)?|int)"
# Reviewed extensions comprise bounded integer/array declarations and direct access expressions.
_HEADER = re.compile(rf"\s*{_TYPE}\s+{_IDENT}\s*\(\s*(?:void)?\s*\)\s*\{{")
_STATEMENTS = [
    rf"{_TYPE}\s+{_IDENT}\s*\[\s*{_NUMBER}\s*\]\s*=\s*\{{\s*0\s*\}}\s*;",
    rf"{_TYPE}\s+{_IDENT}\s*=\s*{_VALUE}\s*;",
    rf"enum\s*\{{\s*{_IDENT}\s*=\s*{_NUMBER}\s*\}}\s*;",
    rf"(?:if\s*\(\s*{_VALUE}\s*(?:>=|<=|==|!=|>|<)\s*{_VALUE}\s*\)\s*)?"
    rf"(?:return\s+{_ATOM}(?:\s*\+\s*{_ATOM})?|{_ATOM}\s*(?:=|\+=)\s*{_ATOM})\s*;",
]
_STATEMENT = re.compile(r"\s*(?:" + "|".join(_STATEMENTS) + ")")
_END = re.compile(r"\s*}")


def _reviewed_subset(source):
    if len(source) > 16384:
        return False
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError:
        return False
    # Line splicing and alternative preprocessor spellings precede C/C++ comment handling.
    if any(x in text for x in ("\x00", "\\", "??", "%:", "#")):
        return False
    code = re.sub(r"/\*.*?\*/|//[^\r\n]*", " ", text, flags=re.S).strip()
    header = _HEADER.match(code)
    if not header:
        return False
    pos = header.end()
    while match := _STATEMENT.match(code, pos):
        pos = match.end()
    end = _END.fullmatch(code, pos)
    return end is not None


def _registration(source, digest, logical_path, entry):
    pinned = digest in _registered().get(logical_path, set())
    if entry is None:
        return {"kind": "builtin_fixture"} if pinned else None
    if not isinstance(entry, dict):
        return None
    staged = entry.get("path")
    if (not _BASENAME.fullmatch(logical_path) or not isinstance(staged, str)
            or not _BASENAME.fullmatch(staged) or Path(staged).suffix != Path(logical_path).suffix
            or entry.get("kind") != "source" or type(entry.get("size")) is not int
            or entry["size"] != len(source) or entry.get("sha256") != digest):
        return None
    if not pinned and not _reviewed_subset(source):
        return None
    return {"kind": "host_manifest", "staging_path": staged, "sha256": digest}


def _span(node, loc="spellingLoc"):
    ends = node["range"]
    first = ends["begin"].get(loc, ends["begin"])
    last = ends["end"].get(loc, ends["end"])
    return [first["offset"], last["offset"] + last["tokLen"]]


def _walk(node, path=(), parents=()):
    yield node, path, parents
    for index, child in enumerate(node.get("inner", [])):
        yield from _walk(child, path + (index,), parents + (node,))


def _point(source, offset):
    return source.count(b"\n", 0, offset) + 1, offset - source.rfind(b"\n", 0, offset)


def _reference(node):
    return next((child["referencedDecl"] for child, _, _ in _walk(node)
                 if child.get("kind") == "DeclRefExpr"), {})


def _operation(node, parents):
    # Parent-child identity distinguishes assignment destination from the value operand.
    for parent in reversed(parents):
        kind = parent["kind"]
        if kind == "ParenExpr":
            node = parent
            continue
        lhs = parent.get("inner", [None])[0] is node
        if lhs and kind == "CompoundAssignOperator":
            return "read_write"
        if lhs and kind == "BinaryOperator" and parent["opcode"] == "=":
            return "write"
        if kind == "ImplicitCastExpr" and parent.get("castKind") == "LValueToRValue":
            return "read"
        break
    raise ValueError("unsupported access operand")


def _origin(node, parents, source):
    spelling = _span(node)
    if "expansionLoc" not in node["range"]["begin"]:
        return {"kind": "source", "spelling_span": spelling}
    expansion = _span(node, "expansionLoc")
    # The reviewed PAIR replacement wraps each parameter occurrence in its own parentheses.
    pair = next(p for p in reversed(parents)
                if p["kind"] == "ParenExpr" and "spellingLoc" in p["range"]["begin"])
    first, last = _span(pair)
    if source[first:last] != b"(x)":
        raise ValueError("unresolved macro replacement occurrence")
    return {"kind": "macro_expanded", "spelling_span": spelling, "expansion_span": expansion,
            "macro": source[slice(*expansion)].decode(), "parameter": "x",
            "replacement_use_span": [first + 1, last - 1]}


def _index(ast, source, identity):
    targets, calls = [], []
    for decl in ast["inner"]:
        if decl["kind"] != "FunctionDecl" or not any(
                n["kind"] == "CompoundStmt" for n in decl.get("inner", [])):
            continue
        enclosing = {"name": decl["name"], "signature": decl["type"]["qualType"],
                     "definition_span": _span(decl), "symbol": decl["mangledName"]}
        ordinal = 0
        for node, path, parents in _walk(decl):
            kind = node.get("kind")
            if kind not in ("ArraySubscriptExpr", "CallExpr"):
                continue
            span = _span(node)
            line, col = _point(source, span[0])
            row = dict(byte_span=span, line=line, column=col, ast_path=list(path),
                       ast_kind=kind, enclosing_decl=enclosing, context_policy="definition")
            if kind == "CallExpr":
                row.update(callee=_reference(node["inner"][0])["name"],
                           callsite_ref=_id("call", identity, enclosing, path))
                calls.append(row)
                continue
            role = _operation(node, parents)
            value_type = node["type"]["qualType"]
            row.update(identity, target_ref=_id("target", identity, enclosing, path, role),
                       operation=role, value_type=value_type, object_name=_reference(node["inner"][0])["name"],
                       width_bytes={"int": 4, "unsigned int": 4, "const volatile unsigned int": 4}.get(value_type),
                       access_ordinal=ordinal, origin_trace=_origin(node, parents, source),
                       mapping_status="origin", mapping_ref=None)
            targets.append(row)
            ordinal += 1
    return targets, calls


def locate(targets, **hint):
    """Return all source candidates matching the supplied location precision."""
    supported = {"line", "column", "byte_span", "ast_path", "target_ref", "operation", "file",
                 "snapshot_ref", "variant_id", "file_digest"}
    if not hint or set(hint) - supported:
        raise ValueError("unsupported or missing location hint")
    found = [r["target_ref"] for r in targets if all(r[k] == v for k, v in hint.items())]
    precise = bool({"target_ref", "byte_span", "ast_path"} & hint.keys() or {"line", "column"} <= hint.keys())
    status = "unmapped" if not found else "ambiguous"
    if precise and len(found) == 1:
        status = "exact_1to1"
    return dict(mapping_status=status, candidate_refs=found)


def _ir_index(ir, calls, targets):
    metadata = dict(re.findall(r"^!(\d+) = (.*)$", ir, re.M))
    points = {}
    for key, value in metadata.items():
        if value.removeprefix("distinct ").startswith("!DILocation("):
            fields = dict(re.findall(r"(line|column|scope|inlinedAt): !?(\d+)", value))
            points[key] = fields
    rows, inline = [], []
    for line in ir.splitlines():
        dbg = re.search(r"!dbg !(\d+)", line)
        op = re.match(r"^\s+(?:%[-\w.]+ = )?(load|store)\b", line)
        if not dbg or not op or dbg[1] not in points:
            continue
        loc = points[dbg[1]]
        row = {"opcode": op[1], "line": int(loc["line"]), "column": int(loc.get("column", 0))}
        scope = metadata.get(loc["scope"], "")
        symbol = re.search(r'!DISubprogram\(name: "([^"]+)"', scope)
        row["definition_name"] = symbol[1] if symbol else None
        chain = []
        while "inlinedAt" in loc:
            loc = points[loc["inlinedAt"]]
            chain.append([int(loc["line"]), int(loc.get("column", 0))])
        row["inlined_at"] = chain
        rows.append(row)
        if chain:
            matches = [c for c in calls if [c["line"], c["column"]] == chain[0]]
            definitions = [r for r in targets if r["enclosing_decl"]["name"] == row["definition_name"]
                           and (r["line"], r["column"]) == (row["line"], row["column"])]
            if len(matches) == 1 and len(definitions) == 1 and matches[0]["callee"] == row["definition_name"]:
                inline.append(dict(row, callsite_ref=matches[0]["callsite_ref"],
                                   definition_target_ref=definitions[0]["target_ref"]))
    return {"ir_sha256": _digest(ir.encode()), "debug_memory_instructions": rows, "inline_instances": inline}


def analyze_source(source: bytes, *, relative_path: str, snapshot_ref: str, variant_id: str,
                   scope_kind: str = "original_source", manifest_entry=None):
    """Index reviewed bytes with fixed syntax/IR actions. manifest_entry is supplied by the
    coordinator from its read-only staged grant. The caller authenticates the grant before
    this call; the frontend checks its content binding and language subset.
    """
    def diagnostic(code, reason):
        return {"status": "diagnostic", "diagnostics": [{"code": code, "reason": reason}]}

    if not isinstance(source, bytes) or not all(isinstance(x, str) and x for x in
                                               (relative_path, snapshot_ref, variant_id)):
        return diagnostic("parse_context_missing", "source bytes and versioned identity required")
    digest = _digest(source)
    registration = _registration(source, digest, relative_path, manifest_entry)
    if registration is None:
        return diagnostic("parse_context_missing", "unregistered unit, digest mismatch or unsupported source profile")
    if scope_kind not in ("original_source", "seed_skeleton", "counterfactual_case"):
        return diagnostic("parse_context_missing", "unsupported scope")
    lang, standard = ("c", "c17") if relative_path.endswith(".c") else ("c++", "c++17")
    flags = ["--no-default-config", "--target=" + TRIPLE, "-x", lang, "-std=" + standard,
             "-nostdinc", "-fno-color-diagnostics", "-Werror", "-fdebug-compilation-dir=."]
    config = dict(adapter=ADAPTER, compiler=CLANG, compiler_version=VERSION, target=TRIPLE,
                  language=lang, standard=standard, flags=flags, headers=[], defines=[])
    identity = dict(scope_kind=scope_kind, snapshot_ref=snapshot_ref, variant_id=variant_id,
                    file=relative_path, file_digest=digest, parse_config_ref=_id("config", config))
    try:
        with tempfile.TemporaryDirectory() as tmp:
            def run(args):
                result = subprocess.run([CLANG, *args], cwd=tmp, env={"LC_ALL": "C", "PATH": "/usr/bin"},
                                        capture_output=True, timeout=20, check=True)
                return result.stdout.decode()
            if run(["--version"]).splitlines()[0] != VERSION:
                return diagnostic("parse_context_missing", "compiler version differs from locked build")
            (Path(tmp) / relative_path).write_bytes(source)
            tree = json.loads(run(flags + ["-fsyntax-only", "-Xclang", "-ast-dump=json", relative_path]))
            targets, calls = _index(tree, source, identity)
            ir = {}
            for level in ("O0", "O2"):
                output = run(flags + ["-" + level, "-g", "-S", "-emit-llvm", relative_path, "-o", "-"])
                ir[level] = _ir_index(output, calls, targets)
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, StopIteration) as error:
        detail = error.stderr.decode(errors="replace")[:1000] if isinstance(error, subprocess.CalledProcessError) else str(error)
        return diagnostic("parse_context_missing", detail)
    return dict(status="ok", source_sha256=digest, registration=registration, config=config,
                targets=targets, calls=calls, ir=ir)
