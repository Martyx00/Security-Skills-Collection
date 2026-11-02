# Output files, in plain language

Everything is written under `sbom-out/` next to the repositories (never into a repository and never into the skill folder); a pilot run (`pilot <repo>...`) writes the same files under `sbom-out-pilot/`, which is a folder of its own with its own `previous/`, `history/` and `abandoned/`. Output files are built in `sbom-out/.staging/<run id>/` and moved to their final place only when the audit passes. If the audit fails they stay in `.staging/` and `sbom-out/report.md` says why. Use this file to explain results to the user; read an output file only when asked.

## What the user gets

| File | Content |
|---|---|
| `sbom-out/repos/<repo>/<repo>.sbom.csv` | One row per component of that repository. |
| `sbom-out/repos/<repo>/<repo>.spdx.json` | The same components as an SPDX 2.3 document. |
| `sbom-out/repos/<repo>/<repo>.cdx.json` | The same components as a CycloneDX 1.6 document. |
| `sbom-out/repos/<repo>/<repo>.delta.csv` | Repeat runs only: what is new, removed or updated since the baseline (below). |
| `sbom-out/repos/<repo>/<repo>.evidence.csv` | Every evidence record behind every candidate, one row per file and line. |
| `sbom-out/repos/<repo>/candidates_audit.csv` | Every candidate, in the SBOM or not, with its class and why. |
| `sbom-out/merged-sbom.csv` | All repositories merged, one row per component and version. |
| `sbom-out/cpe_resolution.csv` | How each CPE was obtained (NVD dictionary name or constructed), per approved pair. |
| `sbom-out/report.md` | The run report: integrity result, warnings, known unknowns, status per repository, conformance and limits. Written on PASS and FAIL. |
| `sbom-out/validation-report.txt` | One line per validation check and the verdict. |
| `sbom-out/local-cpe-decisions.csv` | The approved CPE decisions, reused to pre-fill the next run (written only when the audit passes). |
| `sbom-out/previous/`, `history/<time>/`, `abandoned/<time>/` | The last finished run (the baseline of the next one), the runs before it, and runs that never finished or failed their audit (below). |

Machine-readable state (`sbom-out/.state/`, including `validation.json` and the ledger `runfiles.json`) is for the script; do not read or edit it. Every file below `sbom-out/` is written by the script (the files an `adjudicate` block names and the review file excepted); the script checks that at every command and again in the audit (check `run_folder_unchanged`), and after the run finished it compares the folder with the ledger sealed at the end whenever `next`, `status`, `summary`, `explain` or `audit` runs (a changed script file is reported first as `RUN FOLDER CHANGED since the run finished`).

## Per-repository CSV

Header, in order: `name, version, cpe23, locations, spdx_id, verification, cpe_alternates, purl, upstream_url, upstream_commit, usage, usage_level, scope, identity_confidence, version_confidence, version_source, version_kind, analysis_mode, evidence_types, detection_method, detected_as, sha256, supplier, license_declared, cpe_version_wildcard, cpe_name_source, pair_source, cpe_name_id, notes`.

- One row per component, sorted by name and version. `spdx_id` ties the row to its SPDX package.
- `version` holds only a normalized release (for example `1.3.1`). Every other kind of version (a snapshot, a commit between releases, a constraint such as `>= 3.0`, an unpinned branch, unknown) is written as `NOASSERTION`; the raw text and the kind stay in `version_kind` and `notes`.
- `cpe23` is the `;`-joined list of every emitted CPE, primary first. It is empty on purpose when the component has no NVD product or the human chose `skip`. An unknown version in a CPE is `*` with `cpe_version_wildcard=yes`, never `-`. `cpe_name_source`, `pair_source` and `cpe_name_id` line up with `cpe23` item by item (`dictionary` or `constructed`).
- `cpe_alternates` are suggestions shown for the human; they are not emitted and not compared.
- `locations` are the files, directories and lines that show the component (`path/`, `path:line`).
- `verification`: `proven` (the script's rules showed the component is compiled, linked, loaded or included), `declared` (declared or wired in the build or decided by a model answer, but not proven) or `unresolved` (evidence points toward use but the script could not settle it, or a submodule was not analysed). Only `proven` rows are shipped by default; `declared` and `unresolved` rows are there because the human opted them in.
- `usage`, `usage_level`, `scope`: how and where the component is used (for example static, `vendored_compiled`, scope `product`).
- `notes` are items joined with ` | `.
- Cells that would start like a formula (`=`, `+`, `-`, `@`) carry a leading apostrophe. The file is UTF-8 with a byte order mark and CRLF line endings, so Excel opens it directly.

## SPDX 2.3 JSON

- One root package for the repository (its commit, `describe` string and scrubbed origin URL), one package per component, and relationships. The document is checked against the SPDX 2.3 and 2.3.1 JSON schemas and against extra semantic rules.
- Every CPE is an external reference of type `cpe23Type`; every purl a `purl` reference. Licences come only from the component's own licence file, otherwise `NOASSERTION`; the supplier is `NOASSERTION` unless a vendored SPDX or CycloneDX document names one.
- Locations and provenance (verification, usage, version source, CPE sources) are annotations; the CSV and the SPDX file are checked to agree.
- The root `DEPENDS_ON` a `NOASSERTION` element whose comment lists the known blind spots: the recovered list may be incomplete.
- The creation comment states the generation context ("Source"), the repository status, the approval evidence level (`tty` when the person ran `human_approve.py` in a terminal, `agent-relayed` when the agent ran `approve` after a chat reply; `agent-relayed` is the weaker form), the enforcement statement (a plain skill install has no hook), the NVD data source, the repositories that have no SBOM in this run and the NVD notice. The same evidence level is recorded in `run.json`, `approval.json`, the audit log, `report.md` and the summary.

## CycloneDX 1.6 JSON

- Same components, same identifiers and same facts as the SPDX file, written in the other format. `bom-ref` of a component is its SPDX id without the `SPDXRef-` prefix, so the two files can be joined. The root (`metadata.component`, type `application`) has the commit that was analysed as its `version`; `kiro-sbomber:describe`, `:branch` and `:repository-status` are properties. `kiro-sbomber:` is the name prefix of every property this skill adds.
- The file is deterministic: `serialNumber` is a UUIDv5 of the content (the timestamp is left out of it), so the same inputs give the same serial. A component without a normalized release has no `version`; the raw text and the kind are properties.
- `licenses` holds a `license.id` only for an id of the CycloneDX 1.6 list (`assets/cyclonedx-license-ids.json`), otherwise an `expression`; nothing is looked up. `cpe` is the primary emitted CPE and further emitted CPEs are `kiro-sbomber:cpe-additional` properties; `purl` likewise. `scope` is `required`, `optional` or `excluded` (test, development and build-only dependencies under `start --scope all`).
- `compositions` never says `complete`: a list recovered from source may be incomplete (`incomplete` when the repository has known gaps, otherwise `unknown`). `dependencies` has the root and the components it depends on; `evidence.occurrences` has the locations.
- The shape is checked with the standard library (`cdxcheck`), which is stricter than the official schema on purpose, and the `cyclonedx` validation check compares the document with the CSV. The test suite cross-checks the writer against the official JSON Schema when the `jsonschema` package and the schema files are at hand.

## evidence.csv and candidates_audit.csv

`evidence.csv` columns: `spdx_id, candidate_id, evidence_id, type, strength, path, line, symbol, detail, scope, condition, technique`. `spdx_id` is empty for candidates that are not in the SBOM.

`candidates_audit.csv` columns: `candidate_id, name, version, class, usage_level, scope, reason_code, condition, verification, in_sbom, spdx_id, detected_as, locations, evidence_ids, notes`. This is where to look when a component the user expected is missing. Typical reason codes: `PRESENT_NOT_BUILT` and `DECLARED_NOT_USED` (a dead copy), `TEST_ONLY`, `DEV_ONLY`, `BUILD_ONLY`, `CONDITIONAL_DISABLED` (off in every shipping configuration), `FIRST_PARTY`, `UNINITIALIZED_SUBMODULE`, `NOT_VERIFIED` (declared or unresolved and not opted in), `HUMAN_EXCLUDED` (proven, but the human set `include=no`), and the `REVIEW_*` codes for unsettled cases.

## delta.csv and the baseline

A full run after a finished full run is incremental: `start` moves the finished run to `previous/` (and the one before it to `history/<time>/`), and the new run compares every repository with it. Per repository `repos/<repo>/delta.json` and `<repo>.delta.csv` list `NEW`, `REMOVED` and `UPDATED` components (columns `change, name, version, baseline_version, cause, locations`). `cause` is `code` (a file the component lies in changed between the two commits, a bumped submodule included), `analysis` (the component differs but its files did not: a better rule, a worker claim, a corrected version) or `unverified` (the baseline commit is no longer in the repository's history). Only `code` is a change of the product. A repository the baseline did not analyse has no delta, and the report says so. `report.md` and the summary carry the counts. A run that failed its audit, or was dropped with `start --abandon`, goes to `abandoned/` and is never a baseline; a pilot is never the baseline of a full run, and a full run is never the baseline of a pilot.

## merged-sbom.csv

Header: `name, version, repositories, repo_count, cpe23, purl, usages, locations, versions_seen_all_repos, detected_as, conflicts`.

One row per component name and version across all repositories that were analysed. A component whose version is `NOASSERTION` is never merged across repositories. `locations` are `repo:path[:line]` items. `conflicts` names which of `cpe23`, `purl` or `license` differ between repositories. Failed repositories contribute nothing.

## cpe_resolution.csv

One row per approved pair per review row, plus rows for search-only names. `emitted` says whether the pair went into the outputs; `cpe_name_source` says whether the name is an NVD dictionary name (with its `cpe_name_id`) or constructed; `data_source` is `live-api:<date>`, `offline` or `not-needed`. Keyword candidates for search-only rows are listed in `keyword_candidates` and are never emitted.

## report.md

Fixed order: 1. Integrity result (did anything change in the repositories; changes that the IDE's own Source Control may cause, and changes during a pause, are listed separately and not blamed on the run). 2. Checkout warnings. 3. Known unknowns (never dropped). 4. Per-repository status (commit, branch and the worker's outcome per repository). 5. Submodules (every one that was not checked out is listed as excluded from the analysis, with its pinned commit). 6. Changes since the baseline. 7. CPE coverage. 8. Ignored files (the worker's `IGNORED` and `EXCLUDED` items are listed there too). 9. Approval and enforcement. 10. Output paths. 11. Conformance and limits. A pilot's report starts with `PILOT RUN` and names the repositories.

Warnings come in two tiers, ACTION REQUIRED and INFORMATIONAL. Repository status is `DONE`, `INCOMPLETE` (finished with known gaps, for example an uninitialized submodule), `FAILED` (that repository only; the run continues) or `NOT ANALYZED` (empty or unreadable). Conformance is stated honestly: `NOASSERTION` is used where a value cannot be recovered, so strict NTIA-style checkers will flag it; the CISA minimum elements are counted one by one; Dependency-Track and similar tools can read the CycloneDX file.

## validation-report.txt

One line per check, `PASS`, `FAIL` or `SKIPPED` followed by the check name and the first errors, then the verdict. Checks: SPDX schema, SPDX semantics, CSV = SPDX parity, CycloneDX shape and CSV parity, merged-CSV parity, every submodule accounted for, CPE provenance (only approved pairs), version evidence, repositories unchanged (`targets_unchanged`), pack unchanged (`pack_unchanged`), run folder unchanged (`run_folder_unchanged`: no file the script wrote was changed or deleted, and the ledger is usable). Files below `sbom-out/` that the script did not write do not fail the check; they are listed in `report.md` and as ACTION REQUIRED warnings (`RUN_FOLDER_EXTRA_FILE`; a changed or deleted script file is `RUN_FOLDER_CHANGED`). The verdict is `PASS` only if every check passes. A failed repository alone does not fail the verdict; it is an ACTION REQUIRED item.
