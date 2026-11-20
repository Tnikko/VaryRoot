"""Compile a declarative byte-interval contract into seed-local QL facts."""

import argparse
from collections import Counter
import hashlib
import json
import re
import shutil
from pathlib import Path


_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*$")
_PATH_KEYS = ("payload_path", "logical_length_path", "total_length_path")
_NAME_KEYS = ("function", "copy_api", "destination")
_INT_KEYS = ("target_line", "destination_argument", "source_argument",
             "width_argument", "width_bytes")


def validate_contract(contract: dict) -> dict:
    """Reject missing bindings before query generation, never default a seed role."""
    for key in _NAME_KEYS:
        if not isinstance(contract.get(key), str) or not _IDENTIFIER.fullmatch(contract[key]):
            raise ValueError(f"invalid_{key}")
    for key in _PATH_KEYS:
        path = contract.get(key)
        if not isinstance(path, list) or not 1 <= len(path) <= 4 or any(
            not isinstance(part, str) or not _IDENTIFIER.fullmatch(part) for part in path
        ):
            raise ValueError(f"invalid_{key}")
    for key in _INT_KEYS:
        value = contract.get(key)
        if type(value) is not int or value < (1 if key in ("target_line", "width_bytes") else 0):
            raise ValueError(f"invalid_{key}")
    if len({contract["destination_argument"], contract["source_argument"],
            contract["width_argument"]}) != 3:
        raise ValueError("overlapping_arguments")
    if contract["width_bytes"] > 4096 or contract["target_line"] > 1000000:
        raise ValueError("out_of_range")
    return contract


def _path_predicate(name: str, path: list[str]) -> str:
    current = "e"
    checks = []
    for member in reversed(path):
        access = f"{current}.(FieldAccess)"
        checks.append(f'{access}.getTarget().hasName("{member}")')
        current = f"{access}.getQualifier()"
    checks.append(f"{current}.(VariableAccess).getTarget() = root")
    return f"predicate {name}(Expr e, Variable root) {{\n  " + " and\n  ".join(checks) + "\n}"


def render_contract(contract: dict) -> str:
    validate_contract(contract)
    strings = {
        "targetFunctionName": contract["function"],
        "copyApiName": contract["copy_api"],
        "destinationName": contract["destination"],
    }
    numbers = {
        "targetLine": contract["target_line"],
        "destinationArgument": contract["destination_argument"],
        "sourceArgument": contract["source_argument"],
        "widthArgument": contract["width_argument"],
        "copyWidthBytes": contract["width_bytes"],
    }
    parts = ["import cpp", "// Generated only from the declared seed contract."]
    parts.extend(f'string {name}() {{ result = "{value}" }}' for name, value in strings.items())
    parts.extend(f'int {name}() {{ result = {value} }}' for name, value in numbers.items())
    parts.extend((
        _path_predicate("payloadField", contract["payload_path"]),
        _path_predicate("logicalLengthField", contract["logical_length_path"]),
        _path_predicate("totalLengthField", contract["total_length_path"]),
    ))
    return "\n\n".join(parts) + "\n"


def render_lane(lane: str) -> str:
    if lane not in ("Q0", "Qstar"):
        raise ValueError("unknown_lane")
    alert = "baselineAlert" if lane == "Q0" else "revisedAlert"
    return (
        "import oob_interval\n\n"
        "from FunctionCall copy, string kind\n"
        f'where site(copy) and (kind = "site" or kind = "covered" and guardCovered(copy) or kind = "alert" and {alert}(copy))\n'
        "select copy, kind, copy.getLocation().getStartLine()\n"
    )


def classify_rows(rows: list[dict], target_line: int) -> str:
    """Score only the declared expression; unmapped coverage is a backend gap."""
    selected = Counter(row["kind"] for row in rows if row["line"] == target_line)
    if selected["site"] != 1 or selected["covered"] != 1:
        return "backend_gap"
    if selected["alert"] > 1 or set(selected) - {"site", "covered", "alert"}:
        return "backend_gap"
    return "report" if selected["alert"] == 1 else "quiet"


def compile_package(contract_path: Path, output: Path) -> dict:
    """Write an auditable two-lane package from one contract declaration."""
    contract = json.loads(contract_path.read_text())
    validate_contract(contract)
    output.mkdir(parents=True, exist_ok=True)
    (output / "contract.qll").write_text(render_contract(contract))
    (output / "Q0.ql").write_text(render_lane("Q0"))
    (output / "Qstar.ql").write_text(render_lane("Qstar"))
    shared = Path(__file__).parents[2] / "varyroot/ql07/oob_interval.qll"
    shutil.copyfile(shared, output / "oob_interval.qll")
    (output / "qlpack.yml").write_text(
        "name: varyroot/oob-interval-probe\nversion: 0.0.1\n"
        "dependencies:\n  codeql/cpp-all: 12.2.0\n"
    )
    files = ["contract.qll", "Q0.ql", "Qstar.ql", "oob_interval.qll", "qlpack.yml"]
    manifest = {
        "contract_sha256": hashlib.sha256(contract_path.read_bytes()).hexdigest(),
        "files": {name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in files},
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("contract", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(compile_package(args.contract, args.output), sort_keys=True))
