# Ettercap OOB Feasibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish whether one real Ettercap OOB repair can pass a source build, independent logical-capacity verification, and a reusable two-lane CodeQL feasibility regression without misreporting backend gaps.

**Architecture:** Keep upstream source snapshots and experimental evidence in `runs/step4f-oob-feasibility/`, and keep reusable verifier and QL code in small repository modules. A declarative contract supplies object, source, width, and guard roles to shared predicates. The B decision gates whether candidate Q* may be called final or frozen.

**Tech Stack:** Python 3, Clang 18, Docker, CMake, ASan, CodeQL 2.27.2 with locked `cpp-all` 12.2.0, SQLite coordination where existing interfaces admit the new seed.

**Spec:** `F:\RootVary\server-reports\2026-11-20-step4f-oob-feasibility\design-lock.md` and `registered-domain.json`, following `F:\RootVary\server-reports\2026-11-20-step4e-closeout-oob\oob-design.md`; user approval in the current chat supersedes the old physical-primary proposal.

## Global Constraints

- Primary OOB capacity is the logical payload `disp_len`; physical allocation `disp_len + 1` and target-specific ASan results are separate evidence.
- The target is the second `memcpy(buffer, ptr, 16)` in `WAIT_CHALLENGE`; other calls and later `strstr`/`buf[16]` cannot substitute for it.
- The registered finite domain has 32 combinations; a definite negative requires full coverage and a safe reached target witness.
- Real parent and fixed `ec_vnc.c` must compile in an isolated dependency-pinned container; otherwise stop at `seed_pending`.
- Shared OOB QL and query generation contain no Ettercap field names or literal width 16; per-seed parameters hold those values.
- Any frozen Q₀/Q* pair needs a unique B decision and exact target regression. Otherwise keep the Q* lane explicitly provisional.
- Query limits: 15 minutes and 5 GiB peak RSS per lane; database build limit: 45 minutes. Overrun is `execution_limit`.
- Preserve all prior freeze packages and Step 4 ledger bytes. Save raw evidence and SHA-256 manifests locally under `F:\RootVary\server-reports\` and in the VM `runs/` directory.

## Review Focus

1. `disp_len` and `DATA.len` differ: contract qualification must stop, not use the wrong capacity.
2. `L=19`, `ptr=B+4`, `W=16`: primary logical positive with no claimed physical heap overread.
3. Target `memcpy` is blocked or a later `strstr` fails: observation must identify the target outcome only.
4. A QL database omits the target TU or macro-expanded relation: report a mapped `backend_gap`, not `quiet`.
5. A prototype Q* matches a development target but B remains non-unique: do not freeze or start unseen evaluation.

---

### Task 1: Lock inputs and pass the real-source build gate

**Files:**
- Create: `runs/step4f-oob-feasibility/input/` (outside tracked source; commit hashes, parent/fixed tarballs, toolchain image, commands and logs)
- Create: `tools/oob_feasibility/build.py`
- Test: `tests/test_oob_build.py`

**Interfaces:** `build.py` accepts fixed upstream commit SHAs and an output directory, and emits a JSON record with source hashes, compiler invocation for `ec_vnc.c`, version, exit status and captured TU identity. It must never silently substitute a reduced skeleton.

- [ ] Save the locked domain, source commits, and upstream patch digests to the VM run before building.
- [ ] Write a test that rejects a build record lacking the original `ec_vnc.c` TU or that maps the wrong source SHA; observe it fail before implementation.
- [ ] Prepare a Docker image from a pinned base with `libpcap0.8-dev` and other CMake dependencies, disable GUI/plugins not needed, and capture parent and fixed CMake or exact TU compiler commands separately.
- [ ] Run the same test green and inspect actual build logs. If either version cannot compile, write `seed_pending` with the exact dependency/compiler error and stop Tasks 2–4.
- [ ] Commit reusable build gate code and test; copy all raw logs and image/package identities into local report.

### Task 2: Independently observe the logical and physical boundaries

**Files:**
- Create: `tools/oob_feasibility/observe.py`
- Create: `tools/oob_feasibility/harness/` (driver and any test-only adapters; upstream `ec_vnc.c` remains unmodified)
- Test: `tests/test_oob_observe.py`

**Interfaces:** `observe.py` consumes an immutable `registered-domain.json` and per-case runtime trace; it emits target reached/blocked, `B/end/ptr/L/C/W`, logical verdict, physical classification, ASan attribution, and provenance. Missing traces or incomplete domain stay pending.

- [ ] Write failing tests for L=16/18 physical-plus-logical, L=19 logical-only, L=20 safe reached, and incomplete-domain pending.
- [ ] Compile and drive the original parent/fixed function for all 32 registered cases in the same container. Keep target spans exact and keep `buf` large enough for the later `buf[16]` write; report later `strstr` crashes separately.
- [ ] Prove the producer-to-buffer contract and record actual pointer/length values. Use ASan on reached physical violations and accept only a source read at the registered `memcpy` as corroboration.
- [ ] Run test green, inspect parent/fixed paired traces and require at least one real parent target violation, full fixed-domain coverage and a fixed safe reached witness before seed acceptance.
- [ ] Commit verifier/harness code and tests; archive all case inputs, traces and raw sanitizer logs.

### Task 3: Register predictions and assess B uniqueness

**Files:**
- Create: `tools/oob_feasibility/predictions.py`
- Test: `tests/test_oob_predictions.py`
- Output: `runs/step4f-oob-feasibility/calibration/`

**Interfaces:** predictions consume candidate S₀ and alternatives under the logical-primary contract and emit per-target `report/quiet/uncovered` before independent labels are revealed. Decision output distinguishes hard contradiction, compatible but insufficient coverage, and unresolved multiplicity.

- [ ] Write failing tests that prevent an `iff` physical-capacity interpretation of `end - ptr >= W`, and reject `keep`/`revise` unless exactly one explanation aligns.
- [ ] Register single-factor candidates and all predictions with hashes before reading Task 2 verdicts in the B route; preserve any already observed A4 seed evidence separately from the B candidate evidence.
- [ ] Run the selected cases and independent verifier. If the evidence cannot distinguish surviving explanations, publish `unresolved`; do not nominate a final S*.
- [ ] Commit generic prediction/decision logic only if the existing B interfaces require a genuine reusable extension; otherwise keep experiment-specific registration in the run archive.

### Task 4: Probe shared OOB QL and a second parser

**Files:**
- Create: `varyroot/ql07/oob_interval.qll`
- Create: `tools/oob_feasibility/ql_contract.py`
- Create: `tests/fixtures/oob_unrelated_parser.c`
- Test: `tests/test_oob_codeql.py`

**Interfaces:** `ql_contract.py` validates a declarative object/source/width/guard contract, emits two lane modules with the same shared `.qll`, and returns explicit unsupported relations as `backend_gap`. The second parser uses unrelated names and a different copy width.

- [ ] Write and run a failing real CodeQL regression for total-length versus remaining-length guards in a minimal unrelated parser, including wrong-object and no-target cases.
- [ ] Implement bounded basic-block reachability, same-object binding, byte-width conversion and guarding in shared QL; keep all seed symbols and constants in generated contract data.
- [ ] Build parent/fixed Ettercap databases from the captured real builds within the approved resource limits, run both lanes serially, and align by exact target expression. Report raw alerts and `backend_gap` for each unprovable relation.
- [ ] Run the unrelated parser regression green. Freeze and offline replay only if Task 3 has a unique decision and both lanes pass exact development regression; otherwise publish the QL feasibility matrix as provisional.
- [ ] Commit shared QL, compiler and tests; archive query source, BQRS/CSV, logs, elapsed time and peak RSS.

### Task 5: Synthesize feasibility and interfaces

**Files:**
- Output: `F:\RootVary\server-reports\2026-11-20-step4f-oob-feasibility\review.md`
- Output: matching VM `runs/step4f-oob-feasibility/` report and SHA-256 manifests

- [ ] Run the ordinary full suite and the actual Docker/CodeQL integration tests that apply; inspect all skipped gates.
- [ ] Classify every failure as source/contract, evidence, spec, query implementation, backend, or execution limit; keep denominators and normal safe witnesses visible.
- [ ] State the observed CodeQL boundary and propose a common NPD+OOB Agent A/B interface with declarative object, operation, capacity/source contract, observation adapter, candidate hypotheses, and Decision reasons. Separate recommendation from implemented features.
- [ ] Verify file hashes locally and on VM, review the branch diff, and report the exact status without claiming an OOB freeze if a gate remained open.
