"""Generic locked, pre-oracle C/C++ blind-pool generation entry point."""

import hashlib
import json
import random
import subprocess
import tarfile
from pathlib import Path

from .b_clang_receipt import ast_semantic_sha256, clang_ast, clang_cfg, clang_token_sha256
from .b_interval_ir import make_interval_pair, make_interval_inspector
from .b_model_client import _canonical, _write_once, post_once
from .b_nullable_ir import make_nullable_pair, make_nullable_inspector
from .b_prompt import build_request, hypothesis_pair
from .b_static_retry import run


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def select_pool(rows, budget, random_seeds):
    """Freeze deterministic hard-first and seeded random selections."""
    admitted = [row for row in rows if row["status"] == "admitted"]
    if len(admitted) <= budget or len({row["source_sha256"] for row in admitted}) != len(admitted):
        raise ValueError("insufficient_unique_admitted_pool")
    remaining, chosen, seen_predictions = admitted[:], [], set()
    for _ in range(budget):
        remaining.sort(key=lambda row: (
            not row["hard_divergent"],
            tuple(row["predictions"]) in seen_predictions,
            row["source_sha256"]))
        row = remaining.pop(0)
        chosen.append(row["source_sha256"])
        seen_predictions.add(tuple(row["predictions"]))
    universe = sorted(row["source_sha256"] for row in admitted)
    return {"budget": budget, "divergence": chosen,
            "random": {str(seed): random.Random(seed).sample(universe, budget)
                       for seed in random_seeds}}


def freeze_parameters(policy, result):
    """Use only registered generation and selection budgets."""
    target = policy.get("divergence_target", "hard")
    divergent = result.get(target + "_divergent", 0)
    admitted = result["admitted"]
    ready = (not result["unresolved"] and admitted >= policy["min_admitted"] and
             divergent >= policy["min_divergent"] and
             (not policy.get("require_mixed_scores", False) or 0 < divergent < admitted))
    if not ready:
        return None
    budget, seeds = policy.get("verification_budget"), policy.get("random_seeds")
    if (type(budget) is not int or not 0 < budget < admitted or
            not isinstance(seeds, list) or not seeds or
            any(type(seed) is not int for seed in seeds) or len(seeds) != len(set(seeds))):
        raise ValueError("selection_policy_missing_or_invalid")
    return budget, seeds


def _verify_manifest(path, project):
    manifest = json.loads(Path(path).read_bytes())
    revision = subprocess.check_output(["git", "-C", str(project), "rev-parse", "HEAD"],
                                       text=True).strip()
    if revision != manifest["code_revision"]:
        raise ValueError("code_revision_lock_mismatch")
    for filename, expected in manifest["files"].items():
        source = Path(filename)
        if _sha(source) != expected:
            raise ValueError("prereg_file_lock_mismatch:" + filename)
    return manifest


def run_pool(config_path, *, preflight_only=False):
    """Run one seed with shared prompt, gate, retry and immutable recording."""
    config_path = Path(config_path).resolve(strict=True)
    config = json.loads(config_path.read_bytes())
    project = Path(config["project_root"]).resolve(strict=True)
    manifest = _verify_manifest(config["lock_manifest"], project)
    if str(config_path) not in manifest["files"]:
        raise ValueError("config_not_in_prereg_lock")
    lock = json.loads(Path(config["seed_lock"]).read_bytes())
    seed = config["seed"]
    policy = dict(lock["policy"][seed])
    exclusion = json.loads(Path(config["historical_exclusions"]).read_bytes())
    if _sha(config["historical_exclusions"]) != lock["exclusions_sha256"]:
        raise ValueError("historical_exclusion_lock_mismatch")
    policy["excluded_source_sha256"] = [row["source_sha256"] for row in exclusion["entries"]]
    for key in ("token_sha256", "ast_sha256"):
        policy["excluded_" + key] = [row[key] for row in exclusion["entries"] if row.get(key)]
    before, after = (Path(config["sources"][side]).read_text()
                     for side in ("before", "after"))
    for side, source in (("before", before), ("after", after)):
        key = config["source_lock_keys"][side]
        if hashlib.sha256(source.encode()).hexdigest() != lock["source_sha256"][key]:
            raise ValueError("source_lock_mismatch:" + side)
    family = config["family"]
    if family == "nullable_output":
        packet = make_nullable_pair(config["ir_run_id"], config["subject"])
        specs = packet["specs"]
        first, second = specs["H_check"], specs["H_path"]
    elif family == "interval":
        packet = make_interval_pair(config["ir_run_id"], config["subject"])
        first, second = packet["specs"]["H_total"], packet["specs"]["H_remaining"]
    else:
        raise ValueError("unsupported_contract_family")
    projected = hypothesis_pair(first, second)
    if projected != json.loads(Path(config["pair_projection"]).read_bytes()) or \
            hashlib.sha256(json.dumps(projected, sort_keys=True).encode()).hexdigest() != \
            lock["hypotheses"][seed]["projection_sha256"]:
        raise ValueError("ir_projection_lock_mismatch")
    expected = json.loads(Path(config["request_sample"]).read_bytes())
    actual = build_request(policy, before, after, config["contract"], first, second)
    if actual != expected:
        raise ValueError("request_sample_lock_mismatch")
    if preflight_only:
        return {"seed": seed, "code_revision": manifest["code_revision"],
                "request_sample_sha256": _sha(config["request_sample"]),
                "exclusions_sha256": lock["exclusions_sha256"],
                "policy": lock["policy"][seed]}
    output = Path(config["output_dir"])
    if output.exists() and any(output.iterdir()):
        raise FileExistsError("blind_pool_output_already_started")
    output.mkdir(parents=True, exist_ok=True)
    static_dir = output / "static-compilations"
    static_dir.mkdir()
    placeholders = {}
    for name, archive_path in config.get("header_archives", {}).items():
        if not name.isidentifier():
            raise ValueError("invalid_header_archive_name")
        destination = output / "compile-headers" / name
        destination.mkdir(parents=True)
        with tarfile.open(archive_path) as archive:
            archive.extractall(destination, filter=lambda member, path:
                               tarfile.data_filter(member, path)
                               if member.isfile() or member.isdir() else None)
        placeholders["{header_" + name + "}"] = str(destination)
    counter = 0
    compiled = {}

    def compile_variant(source):
        nonlocal counter
        if source in compiled:
            return compiled[source]
        counter += 1
        path = static_dir / f"source-{counter:03d}.c"
        _write_once(path, source.encode("utf-8"))
        replacements = {**placeholders, "{source}": str(path), "{object}": str(path) + ".o"}
        argv = []
        for template in config["clang_argv"]:
            part = template
            for token, value in replacements.items():
                part = part.replace(token, value)
            argv.append(part)
        try:
            ast, ast_status = clang_ast(argv, str(static_dir), config["function"])
            cfg, cfg_status = clang_cfg(argv, str(static_dir), config["function"]) if ast else (None, None)
        except (OSError, subprocess.TimeoutExpired) as error:
            ast, cfg, ast_status, cfg_status = None, None, {"error": type(error).__name__}, None
        _write_once(static_dir / f"source-{counter:03d}.meta.json",
                    _canonical({"source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                                "ast": ast_status, "cfg": cfg_status}))
        compiled[source] = ast, cfg
        return ast, cfg

    def semantic_fingerprint(source):
        ast, _ = compile_variant(source)
        return {"token_sha256": clang_token_sha256(source),
                "ast_sha256": ast_semantic_sha256(ast) if ast is not None else None}

    parents = {}
    for side, source in (("before", before), ("after", after)):
        ast, cfg = compile_variant(source)
        if ast is None or cfg is None:
            raise ValueError("parent_static_compile_unavailable:" + side)
        parents[side] = (source, ast, config["target_lines"][side])
    if family == "nullable_output":
        inspect = make_nullable_inspector(packet, config["static_config"], parents, compile_variant)
    else:
        inspect = make_interval_inspector(packet, config["static_config"], parents, compile_variant)
    calls = 0

    def invoke(request):
        nonlocal calls
        calls += 1
        return post_once(request, output / "network", calls, config["key_path"], project)

    result = run(before, after, config["contract"], first, second, policy, invoke, inspect,
                 semantic_fingerprint=semantic_fingerprint)
    _write_once(output / "generation-result.json", _canonical(result))
    selection_policy = freeze_parameters(policy, result)
    if selection_policy is not None:
        budget, random_seeds = selection_policy
        frozen = {"seed": seed, "code_revision": subprocess.check_output(
            ["git", "-C", str(project), "rev-parse", "HEAD"], text=True).strip(),
            "generation_sha256": _sha(output / "generation-result.json"),
            "selection": select_pool(result["rows"], budget, random_seeds)}
        _write_once(output / "pool-freeze.json", _canonical(frozen))
    return {"seed": seed, "raw": result["raw"], "admitted": result["admitted"],
            "hard_divergent": result["hard_divergent"], "unresolved": result["unresolved"],
            "pool_frozen": selection_policy is not None}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run_pool(args.config, preflight_only=args.preflight), sort_keys=True))


if __name__ == "__main__":
    main()
