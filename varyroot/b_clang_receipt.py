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
    return location.get("line") or location.get("spellingLoc", {}).get("line") or node.get("loc", {}).get("line")


def _changed_regions(before, after):
    old, new = before.splitlines(), after.splitlines()
    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    return [{"before_lines": list(range(i + 1, j + 1)),
             "after_lines": list(range(k + 1, l + 1)),
             "before_text": "\n".join(old[i:j]), "after_text": "\n".join(new[k:l])}
            for tag, i, j, k, l in matcher.get_opcodes() if tag != "equal"]


def _matches_target(source, tree, line, expression):
    if not isinstance(expression, str) or not expression or line < 1:
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
        bounds = node.get("range", {})
        start, end = bounds.get("begin", {}), bounds.get("end", {})
        if not all(isinstance(value, int) for value in (start.get("offset"), end.get("offset"), end.get("tokLen"))):
            continue
        begin, finish = start["offset"], end["offset"] + end["tokLen"]
        if not 0 <= begin < finish <= len(source):
            continue
        if source.count("\n", 0, begin) + 1 != line:
            continue
        actual = re.sub(r"\s+", "", source[begin:finish]).rstrip(";")
        if actual == expected:
            matches.append(node)
    return len(matches) == 1


def make_receipt(before, after, before_ast, after_ast, target_lines, target_expression,
                 contract_calls=(), cfg=None):
    """Group source edits using actual Clang node kinds and declared target anchors."""
    if not isinstance(target_lines, (tuple, list)) or len(target_lines) != 2 or not all(
            isinstance(line, int) and line > 0 for line in target_lines):
        raise ValueError("target_lines_required")
    if before_ast is None or after_ast is None:
        return {"producer": "clang_ast", "compile_ok": False}
    regions = _changed_regions(before, after)
    nodes = ((list(_walk(before_ast)), list(_walk(after_ast))))
    for region in regions:
        selected = [node for tree, lines in zip(nodes, (region["before_lines"], region["after_lines"]))
                    for node in tree if _line(node) in lines]
        kinds = {node.get("kind") for node in selected}
        text = region["before_text"] + "\n" + region["after_text"]
        roles = set()
        if any(line in lines for line, lines in zip(target_lines, (region["before_lines"], region["after_lines"]))):
            roles.add("target")
        if any(name in text for name in contract_calls) and "CallExpr" in kinds:
            roles.add("contract_call")
        if re.search(r"\b(goto|return|break|continue)\b|^\s*[A-Za-z_]\w*\s*:", text, re.M) and kinds & {"GotoStmt", "LabelStmt", "ReturnStmt", "BreakStmt", "ContinueStmt"}:
            roles.add("control_flow")
        if re.search(r"\b(if|else)\b", text) and "IfStmt" in kinds:
            roles.add("guard")
        if re.search(r"\b(for|while|do)\b|\+\+|--", text) and kinds & {"ForStmt", "WhileStmt", "DoStmt", "UnaryOperator"}:
            roles.add("loop_state")
        if not roles:
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
            "edit_groups": regions, "cfg": cfg}
