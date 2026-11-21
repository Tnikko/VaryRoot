"""Clang AST/CFG evidence for a conservative single-factor admission receipt."""

import difflib
import hashlib
import json
import re
import subprocess


def _replay_command(argv, extra):
    if "-c" not in argv:
        raise ValueError("compile_invocation_required")
    command = []
    skip = False
    for arg in argv:
        if skip:
            skip = False
        elif arg == "-o":
            skip = True
        elif arg != "-c":
            command.append(arg)
    command += ["-fsyntax-only", *extra]
    return command


def clang_ast(argv, cwd, function):
    """Replay declared compiler arguments in syntax-only AST mode."""
    if not function:
        raise ValueError("function_required")
    command = _replay_command(argv, ["-Xclang", "-ast-dump=json",
                                     "-Xclang", "-ast-dump-filter=" + function])
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=120)
    if result.returncode:
        return None, {"exit_code": result.returncode, "stderr": result.stderr[-2000:]}
    decoder = json.JSONDecoder()
    trees, offset = [], 0
    try:
        while offset < len(result.stdout):
            remaining = result.stdout[offset:]
            leading = len(remaining) - len(remaining.lstrip())
            offset += leading
            if offset == len(result.stdout):
                break
            tree, used = decoder.raw_decode(result.stdout, offset)
            trees.append(tree)
            offset += used
    except json.JSONDecodeError:
        return None, {"exit_code": 0, "stderr": "invalid_ast_dump"}
    matches = [tree for tree in trees if tree.get("kind") == "FunctionDecl" and
               tree.get("name") == function and
               any(child.get("kind") == "CompoundStmt" for child in tree.get("inner", []))]
    if len(matches) != 1:
        return None, {"exit_code": 0, "stderr": "ambiguous_or_missing_ast"}
    tree = matches[0]
    return tree, {"exit_code": 0, "ast_sha256": hashlib.sha256(result.stdout.encode()).hexdigest()}


def clang_cfg(argv, cwd, function):
    """Return Clang's unmodified basic-block graph for one named function."""
    if not function:
        raise ValueError("function_required")
    command = _replay_command(argv, ["-Xclang", "-analyze", "-Xclang",
                                     "-analyzer-checker=debug.DumpCFG"])
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=120)
    if result.returncode:
        return None, {"exit_code": result.returncode, "stderr": result.stderr[-2000:]}
    blocks, active, found = {}, None, False
    header = re.compile(r"\b" + re.escape(function) + r"\([^)]*\)\s*$")
    for line in result.stderr.splitlines():
        if not found:
            found = bool(header.search(line))
            continue
        match = re.match(r"^ \[B(\d+)(?: [^]]+)?\]", line)
        if match:
            active = match.group(1)
            blocks[active] = {"id": active, "body": "", "succs": []}
        elif active is not None and re.match(r"^\s+Succs \(\d+\):", line):
            blocks[active]["succs"] = re.findall(r"\bB(\d+)\b", line)
        elif active is not None and line.startswith(" "):
            blocks[active]["body"] += line + "\n"
        elif line and not line.startswith(" "):
            break
    if not blocks:
        return None, {"exit_code": 0, "stderr": "named_cfg_unavailable"}
    return {"producer": "clang_cfg", "blocks": blocks,
            "cfg_sha256": hashlib.sha256(result.stderr.encode()).hexdigest()}, {"exit_code": 0}


def _walk(node):
    if isinstance(node, dict):
        yield node
        for child in node.get("inner", []):
            yield from _walk(child)


def _line(node):
    location = node.get("range", {}).get("begin", {})
    return (location.get("line") or location.get("expansionLoc", {}).get("line") or
            location.get("spellingLoc", {}).get("line") or node.get("loc", {}).get("line"))


def _node_line(node, source):
    explicit = _line(node)
    if explicit is not None:
        return explicit
    offset = node.get("range", {}).get("begin", {}).get("offset")
    raw = source.encode("utf-8")
    return raw.count(b"\n", 0, offset) + 1 if isinstance(offset, int) and 0 <= offset < len(raw) else None


def _node_source(node, source):
    bounds = node.get("range", {})
    start, end = bounds.get("begin", {}), bounds.get("end", {})
    start = start.get("expansionLoc", start)
    end = end.get("expansionLoc", end)
    begin, finish, width = start.get("offset"), end.get("offset"), end.get("tokLen")
    raw = source.encode("utf-8")
    if not all(isinstance(value, int) for value in (begin, finish, width)) or not 0 <= begin < finish + width <= len(raw):
        return None
    return raw[begin:finish + width].decode("utf-8", errors="replace")


def _after_line(before, after, before_line):
    matcher = difflib.SequenceMatcher(None, before.splitlines(), after.splitlines(), autojunk=False)
    for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes():
        if old_start <= before_line - 1 < old_end:
            if tag == "equal":
                return new_start + before_line - old_start
            old_lines, new_lines = before.splitlines(), after.splitlines()
            if tag == "replace" and old_end - old_start == new_end - new_start and all(
                    re.sub(r"\s+", "", old_lines[old_start + n]) ==
                    re.sub(r"\s+", "", new_lines[new_start + n])
                    for n in range(old_end - old_start)):
                return new_start + before_line - old_start
            return None
    return None


def _changed_regions(before, after):
    old, new = before.splitlines(), after.splitlines()
    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    return [{"before_lines": list(range(i + 1, j + 1)),
             "after_lines": list(range(k + 1, l + 1)),
             "before_text": "\n".join(old[i:j]), "after_text": "\n".join(new[k:l])}
            for tag, i, j, k, l in matcher.get_opcodes() if tag != "equal"]


def _ast_shape(value):
    """Erase source coordinates and Clang IDs, retaining semantic AST fields."""
    if isinstance(value, dict):
        if value.get("kind") == "ParenExpr" and len(value.get("inner", [])) == 1:
            return _ast_shape(value["inner"][0])
        return {key: _ast_shape(item) for key, item in value.items()
                if key not in ("id", "loc", "range", "referencedMemberDecl",
                               "parentDeclContextId", "previousDecl")}
    if isinstance(value, list):
        return [_ast_shape(item) for item in value]
    return value


def ast_semantic_sha256(ast):
    """Hash a single Clang function AST without locations or redundant parens."""
    if not isinstance(ast, dict) or ast.get("kind") != "FunctionDecl":
        raise ValueError("function_ast_required")
    payload = json.dumps(_ast_shape(ast), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def clang_token_sha256(source):
    """Hash Clang raw tokens after excluding comments and whitespace."""
    process = subprocess.run(["clang-18", "-x", "c", "-Xclang", "-dump-raw-tokens",
                              "-fsyntax-only", "-"], input=source, text=True,
                             capture_output=True, timeout=120)
    tokens = []
    pattern = re.compile(r"(?m)^(\w+) '(.*?)'\s*(?:\[StartOfLine\]\s*)?Loc=<", re.S)
    for match in pattern.finditer(process.stderr):
        kind, spelling = match.groups()
        if kind == "comment" or kind == "unknown" and not spelling.strip():
            continue
        tokens.append((kind, spelling))
    if process.returncode or not tokens:
        raise ValueError("clang_token_dump_unavailable")
    return hashlib.sha256(json.dumps(tokens, ensure_ascii=False,
                                   separators=(",", ":")).encode("utf-8")).hexdigest()


def _node_state_effect(node, source, contract_calls=()):
    kind = node.get("kind")
    if kind == "CompoundAssignOperator" or kind == "BinaryOperator" and node.get("opcode") in \
            {"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="}:
        return True
    if kind == "UnaryOperator" and node.get("opcode") in ("++", "--"):
        return True
    if kind == "VarDecl" and node.get("init") is not None:
        return True
    if kind == "CallExpr":
        return not any(re.search(r"\b" + re.escape(name) + r"\s*\(",
                                 _node_source(node, source) or "") for name in contract_calls)
    return False


def _loop_condition_only(nodes, region, before, after):
    """Prove that a changed loop header affects only its condition subtree."""
    loops = [[node for node in tree if node.get("kind") in ("ForStmt", "WhileStmt")]
             for tree in nodes]
    if len(loops[0]) != len(loops[1]):
        return None
    for old, new in zip(*loops):
        if old["kind"] != new["kind"]:
            continue
        index = 2 if old["kind"] == "ForStmt" else 0
        old_parts, new_parts = old.get("inner", []), new.get("inner", [])
        if len(old_parts) != len(new_parts) or len(old_parts) <= index:
            continue
        old_condition, new_condition = old_parts[index], new_parts[index]
        if not isinstance(old_condition, dict) or not isinstance(new_condition, dict):
            continue
        if (_node_line(old_condition, before) not in region["before_lines"] or
                _node_line(new_condition, after) not in region["after_lines"] or
                _ast_shape(old_condition) == _ast_shape(new_condition)):
            continue
        if all(_ast_shape(a) == _ast_shape(b) for j, (a, b) in
               enumerate(zip(old_parts, new_parts)) if j != index):
            return not (any(_node_state_effect(child, before) for child in _walk(old_condition)) or
                        any(_node_state_effect(child, after) for child in _walk(new_condition)))
    return None


def _whitespace_only_region(region, nodes, before, after):
    if re.sub(r"\s+", "", region["before_text"]) != re.sub(r"\s+", "", region["after_text"]):
        return False
    old_nodes = [_ast_shape(node) for node in nodes[0]
                 if _node_line(node, before) in region["before_lines"]]
    new_nodes = [_ast_shape(node) for node in nodes[1]
                 if _node_line(node, after) in region["after_lines"]]
    return old_nodes == new_nodes


def _matches_target(source, tree, line, expression):
    if not isinstance(expression, str) or not expression or not isinstance(line, int) or line < 1:
        return False
    lines = source.splitlines()
    if line > len(lines) or expression not in lines[line - 1]:
        return False
    expected = re.sub(r"\s+", "", expression).rstrip(";")
    matches = []
    for node in tree:
        if node.get("kind") not in {"CallExpr", "MemberExpr", "ReturnStmt",
                                    "ArraySubscriptExpr", "UnaryOperator", "BinaryOperator"}:
            continue
        if _node_line(node, source) != line:
            continue
        snippet = _node_source(node, source)
        if snippet is None:
            continue
        actual = re.sub(r"\s+", "", snippet).rstrip(";")
        if actual == expected:
            matches.append(node)
    return len(matches) == 1


def make_receipt(before, after, before_ast, after_ast, target_lines, target_expression,
                 contract_calls=(), cfg=None):
    """Group source edits using actual Clang node kinds and declared target anchors."""
    if isinstance(target_lines, int) and target_lines > 0:
        target_lines = (target_lines, _after_line(before, after, target_lines))
    elif not isinstance(target_lines, (tuple, list)) or len(target_lines) != 2 or not all(
            isinstance(line, int) and line > 0 for line in target_lines):
        raise ValueError("target_lines_required")
    if before_ast is None or after_ast is None:
        return {"producer": "clang_ast", "compile_ok": False}
    nodes = ((list(_walk(before_ast)), list(_walk(after_ast))))
    regions = [region for region in _changed_regions(before, after)
               if not _whitespace_only_region(region, nodes, before, after)]
    for region in regions:
        selected_by_side = [[node for node in tree if _node_line(node, source) in lines]
                            for tree, lines, source in zip(nodes,
                                (region["before_lines"], region["after_lines"]), (before, after))]
        selected = selected_by_side[0] + selected_by_side[1]
        after_selected = selected_by_side[1]
        kinds = {node.get("kind") for node in selected}
        text = region["before_text"] + "\n" + region["after_text"]
        roles = set()
        loop_condition = _loop_condition_only(nodes, region, before, after)
        if any(line in lines for line, lines in zip(target_lines, (region["before_lines"], region["after_lines"]))):
            roles.add("target")
        if any(name in text for name in contract_calls) and "CallExpr" in kinds:
            roles.add("contract_call")
        if re.search(r"\b(goto|return|break|continue)\b|^\s*[A-Za-z_]\w*\s*:", text, re.M) and kinds & {"GotoStmt", "LabelStmt", "ReturnStmt", "BreakStmt", "ContinueStmt"}:
            roles.add("control_flow")
        if loop_condition is True or re.search(r"\b(if|else)\b", text) and "IfStmt" in kinds:
            roles.add("guard")
        if loop_condition is False:
            roles.add("unrelated")
        if loop_condition is None and re.search(r"\b(for|while|do)\b|\+\+|--", text) and kinds & {"ForStmt", "WhileStmt", "DoStmt", "UnaryOperator"}:
            roles.add("loop_state")
        side_effect = loop_condition is None and any(
            _node_state_effect(node, after, contract_calls) for node in after_selected)
        if side_effect:
            roles.add("unrelated")
        region["roles"] = sorted(roles)
        region["contains_goto"] = "GotoStmt" in kinds and bool(re.search(r"\bgoto\b", text))
    # A newly introduced label used only by one new goto belongs to that
    # control-flow edit even when the label is in a separate source hunk.
    new_gotos = re.findall(r"\bgoto\s+([A-Za-z_]\w*)\s*;", after)
    old_gotos = set(re.findall(r"\bgoto\s+([A-Za-z_]\w*)\s*;", before))
    for label in set(new_gotos) - old_gotos:
        if new_gotos.count(label) != 1 or re.search(r"^\s*" + re.escape(label) + r"\s*:", before, re.M):
            continue
        owner = [r for r in regions if re.search(r"\bgoto\s+" + re.escape(label) + r"\s*;", r["after_text"])]
        label_region = [r for r in regions if re.search(r"^\s*" + re.escape(label) + r"\s*:", r["after_text"], re.M)]
        if len(owner) == len(label_region) == 1 and owner[0] is not label_region[0]:
            owner[0]["roles"] = sorted(set(owner[0]["roles"]) | set(label_region[0]["roles"]))
            owner[0]["contains_goto"] = True
            regions.remove(label_region[0])
    bound = all(_matches_target(source, tree, line, target_expression)
                for source, tree, line in zip((before, after), nodes, target_lines))
    return {"producer": "clang_ast", "compile_ok": True,
            "target_binding": "exact_1to1" if bound else "unproven",
            "target_lines": list(target_lines), "edit_groups": regions, "cfg": cfg}
