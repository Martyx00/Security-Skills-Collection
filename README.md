# Security-Skills-Collection

Security review skills for AI coding agents. They work with any agent that loads Agent Skills: Claude Code, Codex, Copilot, Cursor, Gemini CLI, Kiro, Mistral Vibe, OpenCode and others.

## Install

You need Python 3.9 or newer and git; `code-security-review` needs Python 3.11 or newer and ripgrep (`rg`). `binary-vuln-research` uses the binary tools you already have (`readelf`, `objdump`, a decompiler, and a debugger or probe if you want findings verified).

```
git clone https://github.com/Martyx00/Security-Skills-Collection
cd Security-Skills-Collection
python3 install.py <agent> <target> [--skill name,name]
```

- `<target>` is `~` to install for your user, or the path of a project to install into that project only.
- `<agent>` decides where the skills are copied:

  | `<agent>` | Folder |
  |---|---|
  | `claude` | `.claude/skills/` |
  | `kiro` | `.kiro/skills/` |
  | `cursor` | `.cursor/skills/` |
  | `agents` (also `codex`, `copilot`, `gemini`, `vibe`, `opencode`, `cline`, `qwen`,`muse`) | `.agents/skills/` |

- Leave out `--skill` to install all five skills.
- Example: `python3 install.py claude ~/work/my-app --skill report-triage`.

Alternatively, use the `skills` CLI: `npx skills add Martyx00/Security-Skills-Collection -s <skill>`.

Start a new agent session after installing. Gemini CLI and Vibe load project skills only from folders you have marked as trusted.

## Using the skills

Start the agent in the folder you want analysed and ask in plain words; the matching skill loads by itself. When a skill stops for a decision or an approval, answer in the chat. A skill never makes those decisions for you. Results go to a folder in the working directory. The skills' instructions tell the agent to keep its own temporary files out of your repository, but nothing enforces this. Each skill's `references/limitations.md` lists what a plain skill install cannot enforce.

### report-triage

Decides whether an inbound vulnerability report really affects this repository, and whether the defect can be reached in the product. It extracts what the report claims and checks every named symbol, file, CVE and version against the code. When the report names no code, it searches for the code anyway. It tries to disprove any "not affected" verdict and checks every cited line mechanically. It works offline and sends nothing to anyone.

- Run it from the repository the report is about. Paste the report, or keep the file outside the repository or in `.report-triage/inbox/`.
- Ask: *"Triage the vulnerability report in ~/reports/report.txt: is it real, are we affected?"*
- You get `.report-triage/ASSESSMENT-<id>.md` with a verdict and a draft reply; you send any reply yourself. Do not commit `.report-triage/`. Reports are often embargoed, which is why the skill adds a `.gitignore` there.

### sbom-recovery

Recovers a software bill of materials for every C/C++ git repository directly inside the current folder. Each repository gets a CSV, an SPDX 2.3 file and a CycloneDX 1.6 file with evidence. The whole run adds a merged CSV, a CPE table and a report. It finds vendored libraries, submodules, FetchContent, Conan and vcpkg dependencies and firmware inputs, without modifying the repositories. A repeat run reports what changed since the last one.

- Run it from the folder that contains the repositories. Ask: *"Recover SBOM for all top level repositories in this directory"*, or *"Run an SBOM pilot on repoA and repoB"* to try a few repositories first.
- The run stops at a review gate. Check and edit the review file it names (the components it will look up in the NVD), then approve. The strongest way is to run the `human_approve.py` command it prints in a terminal, type `APPROVE`, and reply *"continue"*. You can also reply *"approved"* in the chat.
- Results go to `sbom-out/` (`sbom-out-pilot/` for a pilot). Without network access the NVD lookup is skipped, and the run finishes and says so. Ask *"Where does the SBOM run stand?"* at any time.

### stride-design-review

Security review of a folder of design documents (specifications, architecture, protocols, APIs, devices or ML systems) using STRIDE. It models the documented system, its adversaries and assumptions, then runs an independent gap review and coverage sweep. Every issue goes to a fresh verifier, and every quote is checked byte for byte against the documents. The final report's decision is derived by rule: Insufficient documentation, Approve with conditions, or Approve. It reads the documents only and sends nothing.

- Put the documents in one folder and run the agent from its parent. Ask: *"Threat model this design, the documents are in design/."*
- Narrower requests also work:
  - *"Only do Stage 1 of a STRIDE review of design/"*
  - *"Gap-review this Stage 1 report"*
  - *"Verify issue S1-004"*
  - *"Finalize Stage 3 from these two reports"*
- The result is a run folder in the working directory with `final-review.md`.

### code-security-review

A five-stage, function-level security review of the repository you are in. It maps the attack surface, extracts every function with its rule hits, and ranks every function with an AI pass. Validators that default to "not vulnerable" judge the rule matches. They also judge, as logic-flaw candidates (`LOG-TRI`), the functions the AI rates high but no rule matches, such as a webhook handler that never checks its signature. An arbiter checks the results, and your decisions are kept in a ledger for the next run. It can also judge a single function or finding, and it never changes your code.

- Run it in the repository and ask: *"Run a security review of this repository"*, or for one function: *"Is copy_name in src/util.c vulnerable?"*
- A full review stops three times for you. You choose the scope profile, then how many ranked functions go forward (the cut), then you decide each finding at the review.
- At the cut, each row shows how many of its validator calls are `LOG-TRI`. To skip them, say e.g. *"take the high row without the LOG-TRI candidates"*.
- The report is `.security-review/REPORT.md`. Commit `.security-review/ledger/` to keep your decisions for the next run.

### binary-vuln-research

Vulnerability research on compiled code you have no source for: firmware images and flash dumps, vendor SDK blobs and object archives, stripped executables, shared libraries and drivers, plus the shipped source on the other side of that binary boundary (host drivers, supplicants, IPC producers and consumers, SDK APIs). It hashes every artifact, sweeps it for sixteen defect patterns and reads the trust-deciding functions at each boundary. Each candidate is tiered by reachability and handed to a fresh refuter that does not see why it was raised. A candidate is killed only on positive evidence, and every kill is listed beside the findings. Each finding carries a CVSS lower bound with its arithmetic and a section on what it does not show. Every address, symbol, source line and hash a finding quotes goes in a block that a bundled script re-reads against the artifact, so a wrong base, a byte-order slip or an off-by-one line is caught before you see the finding. It never patches the target and never submits anything.

- Run it from the folder that holds the artifacts. Say what you are authorised to test and who the attacker is. It stops after intake for you to confirm the scope, the targets and the attacker model before any analysis.
- Ask: *"Audit the Wi-Fi firmware blob and the host driver in vendor-sdk/ for memory corruption a nearby attacker can reach. It is in scope of the vendor's bug bounty."*
- Verification on a debugger, emulator or JTAG/SWD/UART target is optional and comes last. After the draft summary you pick which findings to verify, and each experiment waits for you to approve its written brief: nothing touches a live target before that. Irreversible actions (eFuse burns, unlock or mass erase, flash writes, fault injection) are never taken. Every rule is an instruction the agent follows, so keep your agent's permission prompts on for probe, flash and radio tools.
- You get `.binary-vuln-research/`: a finding file per raised candidate, a brief per experiment, and a round summary with every candidate's verdict, kills included. Do not commit it: it holds unreported vulnerabilities, which is why the skill writes a `.gitignore` there. Found secrets are recorded by type, length, first and last four characters and hash, never in full. A submission package and a cover email are written only when you ask, and you send them yourself.
- The citation check is an instruction the agent follows, not a gate: the round summary prints its result line, and you can rerun it from the folder that holds `.binary-vuln-research/` with `python3 -I -B <skill folder>/scripts/verify_citations.py` (exit 0 means every citation and excerpt line re-read correctly against the artifact, and no finding quotes an address, file:line or hash that its citations lack; in a summary or brief an uncited one is only a warning, and what the quoted bytes mean is never checked).
