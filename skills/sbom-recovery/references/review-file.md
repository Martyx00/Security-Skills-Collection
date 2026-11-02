# The review file: `sbom-out/review/cpe-lookup-names.csv`

(`sbom-out-pilot/review/cpe-lookup-names.csv` in a pilot run; everything below is the same there.)

This is the one file the human edits, and the only human step of a run. The script writes it, pauses at `stop_for_approval`, and reads it back strictly after the human replies "approved". You (the agent) never edit it; the human edits and saves it in the editor, a spreadsheet or any CSV tool. (A plain skill install cannot stop an agent from writing the file. The approval records which cells differ from what the script wrote, in `approval.json` and `report.md`, but not who made the change.)

## What approving means

- **Disclosure.** Approval authorizes sending the name and version (and `search_name`) of every row with `include=yes` and `action=lookup` to the NVD Products API. Nothing is sent to NVD before approval, and nothing that is not approved is sent afterwards. No other third party is contacted by this version.
- **What is emitted.** Approval emits the pairs in `proposed_vendor_products` (replaced by `cpe_override` when that cell is set), plus every pair typed into `extra_vendor_products` and every pair entered as `vendor_hint` with `product_hint`. Pairs listed only in `alternatives` (Low tier, model hints, withheld umbrella or toolchain pairs) are never emitted unless the human copies them into one of those cells.
- **Approving without edits** ships only the rows that are pre-set `include=yes`, which are the rows with `verification=proven` (class `USED` decided by the script's rules). Rows with `verification=declared` or `unresolved` are pre-set `include=no`; they are shown so the human can opt them in, and they carry that label in the outputs.
- **Rows that came from the worker role** (reason `REVIEW_WORKER_CLAIM`) are components the script's own rules did not find: the worker read an IDE project, a linker map or a flashed image and named them with citations the script checked against the tree. They are always `include=no` here, `verification=declared` when every citation checked out at a link or compile level (levels L1 to L3) and `unresolved` otherwise. `evidence_summary` says "reported by the worker role (level ...)" and, where the worker wrote them, "worker-reported licence ... (not verified by the script)". Set `include` to `yes` to put such a row into the SBOM; its licence and supplier stay `NOASSERTION` because the script reads a licence only from the component's own licence file. A worker claim that repeats something the script already found adds evidence to that row and changes nothing else about it.

## Rows, columns and how to edit them

One row per component name and version across all repositories. The first three lines of the file are comment lines (they start with `#`, or with `"#` when they contain commas); they repeat the disclosure, what approval emits, and the editable columns. Keep them or delete them; the reader skips every leading comment line.

Editable columns (everything else is ignored when the file is read back, even if changed):

| Column | Values | Meaning |
|---|---|---|
| `include` | `yes` or `no` | `no` excludes the row from every repository. `yes` includes it. |
| `include_in` | `;`-separated repository names, a subset of `repositories` | Narrows an `include=yes` row to those repositories. Empty means every repository of the row. Ignored when `include=no`. |
| `action` | `lookup`, `skip` or `manual` | `lookup`: use the proposals and ask NVD. `skip`: emit no CPE and ask nothing. `manual`: emit only the pairs the human typed, ask nothing. |
| `search_name` | up to 128 characters | A name to list keyword candidates for when no pair is proposed. Candidates are listed in `cpe_resolution.csv`, never emitted. |
| `vendor_hint`, `product_hint` | letters, digits, `.`, `_`, `-` | A human-chosen pair to emit (both cells needed). |
| `part_hint` | `a`, `o`, `h` or empty | CPE part for the hint pair; empty means `a`. |
| `cpe_override` | a full CPE 2.3 string | Replaces the proposals of the row. |
| `cpe_version_override`, `cpe_update_override` | a CPE attribute value | Forces the version or update field of the emitted CPEs (a row with an unknown version otherwise gets `*` and is flagged `cpe_version_wildcard=yes`). |
| `extra_vendor_products` | `;`-separated `[part:]vendor:product` | More pairs to emit for this row. |

Inclusion rule: `include=no` excludes the row from every repository, whatever `include_in` says. `include=yes` with a non-empty `include_in` includes it in exactly the listed repositories. `include=yes` with an empty `include_in` includes it in every repository of the row. So `include_in` only narrows an `include=yes` row; flipping one cell to `no` always excludes.

Rules of thumb:

- To opt a declared or unresolved row in: set `include` to `yes`. To limit it to some repositories, also fill `include_in`.
- To drop a row: set `include` to `no`. Never delete rows (a missing row is refused).
- To add a CPE the map does not know: fill `vendor_hint` and `product_hint`, or `extra_vendor_products`, or `cpe_override`. The model's hints appear only in `alternatives`; copy one into an editable cell to use it.
- Rows with `action=skip` were pre-set because there is no NVD product (curated map) or the component looks internal. Change `action` to `lookup` and add a pair to override that.

Read-only columns give the identity and the evidence: `id` (the join key; never change it), `name`, `version`, `version_kind`, `upstream_commit`, `verification`, `reason` (per repository reason code, or why the row is pre-set to `no` or `skip`), `repositories`, `proposed_vendor_products`, `tier`, `basis`, `alternatives`, `version_in_dictionary` (`unknown` before approval), `nvd_cve_count`, `version_confidence`, `upstream_url`, `purl`, `previously_approved` and `evidence_summary`. A leading `model:` in `evidence_summary` means a model answer decided the row (its `verification` is `declared`).

## How to approve

1. Edit and save the file. Saving without changes is fine.
2. Reply "approved" in the same chat (or a new chat in the same workspace). The agent then runs the approval step; the approval is recorded as `agent-relayed`.
3. Strong form (recommended): the human runs `scripts/human_approve.py` of the skill in a terminal, from the workspace folder (the gate message prints the exact line), types APPROVE, then replies "continue" in the chat. The approval is recorded as `tty`. The agent never runs that script. It is a speed bump, not a security boundary (`limitations.md`).

A reply that is a question, or a reply made before the last edit, does not approve. If the file is edited after approval, the run goes back to the gate and the human approves again; the old approval is kept in the audit trail. A completed run cannot be re-approved: start a new run, whose review file pre-fills the CPE decisions of audited runs (marked `previously_approved=yes`).

## If the file is refused

The message names the code, line, row and column. Fix the file, save it, reply "approved" again.

| Code | Fix |
|---|---|
| `NON_UTF8` | Save as CSV UTF-8 (Excel: File > Save As > CSV UTF-8). |
| `BAD_HEADER` | Restore the header row exactly; do not rename, add, remove or reorder columns. Comma or semicolon delimiters are both accepted. |
| `BAD_ROW_LENGTH` | A row has too many or too few cells (often an unquoted comma or semicolon in a cell). |
| `EMPTY` | The file has no header; restore it. |
| `DUPLICATE_ID`, `UNKNOWN_ID`, `MISSING_ID` | Row ids must be unchanged, unique and present; do not delete or copy rows. |
| `BAD_VALUE` | A cell has a value outside its allowed set (`include`: yes or no; `action`: lookup, skip or manual). |
| `BAD_INCLUDE_IN` | `include_in` lists a repository that is not in the row's `repositories`. |
| `BAD_CPE` | `cpe_override`, `cpe_version_override` or `cpe_update_override` is not a valid CPE 2.3 value. |
| `BAD_PAIR` | An `extra_vendor_products` item is not `[part:]vendor:product`. |
| `BAD_HINT` | `vendor_hint`, `product_hint` or `part_hint` has characters outside the allowed set. |
| `REVIEW_MISSING` | The review file cannot be read at `sbom-out/review/cpe-lookup-names.csv`. Put it back (a saved copy is fine), or abandon the run from a terminal and start again. |
| `FILE_CHANGED` | (`human_approve.py` only) The file changed after it was shown; run it again. |

Spreadsheets: leading apostrophes are how the script protects cells that start with `=`, `+`, `-` or `@`; leave them. Excel in a semicolon locale re-saves the file with `;`; that is accepted. Changes to read-only columns (for example a version `1.10` re-saved as `1.1`) are reported and ignored.
