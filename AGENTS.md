# VaryRoot Engineering & Research Rules

## 1. Research Integrity (Strict)
- Never leak dynamic oracle labels, historical verdicts, CVE/GHSA IDs, URLs, or audit hashes into LLM prompts.
- Never tune queries on unseen evaluation repos and still count them as unseen.
- Analyzers and gates must fail closed: return `undetermined` or `backend_gap` on unevaluated bounds, unsupported syntax, or missing proof. Never silently treat unknown constructs as "no guard" or "safe".

## 2. Anti-Bloat & No Over-Defensive Code (Strict)
- Do not add per-CVE Python modules (e.g., `openldap_*.py`, `ettercap_*.py`). New seeds must plug into shared core via declarative configs.
- Do not add redundant type/range/constant checks on internal functions, speculative unused abstractions, or duplicated helpers.
- Prefer small, direct edits; merge duplicated logic instead of copy-pasting.

## 3. Minimal Auditing & Hashing
- Do not run repeated SHA-256 checks, nested lock manifests, or fragile `mtime` checks inside runtime code.
- Compute SHA-256 manifests and full tar archives only for final frozen bundles or formal paper-experiment checkpoints.

## 4. Checkpoint Deliverables
- For routine dev/fix checkpoints, report only: commit SHA / diff summary, test command results, and key metric counts.
- Do not pack full multi-thousand-file tars, git bundles, or multi-file lock suites unless explicitly requested for a formal experiment archive.
