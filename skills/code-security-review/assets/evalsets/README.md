# `assets/evalsets/` — the frozen evaluation sets

One JSON file per evaluation set, named `<id>.json`. This directory is the
registry `score_functions.py` consults before it allows any run to write
`score_kind: "probability"`. While it holds no calibration — and today it holds
none — every score this skill produces is an ordering and says so, which is the
correct state until somebody has actually measured a classifier.

```bash
python3 -I -B <skill folder>/scripts/score_functions.py --root . --backend finetuned \
    --config scorers.json      # shaped like assets/scorers.example.json
# scorer-report.json → downgrades: [{"code": "no_evalset", "reason": "…"}]
```

---

## What an evaluation set is

A fixed list of functions with known labels, plus the operating points somebody
measured on it. It is **not** a test suite and it is not re-generated: it is the
one artefact in this pipeline that says what a number means, and it can only do
that if it is older than everything it is used to judge.

## The schema

`score_functions.py` requires all seven fields, and checks their values: a file
missing one, or carrying one that measures nothing, is not a calibration, and
the run downgrades with `no_evalset` naming what is wrong.

```json
{
  "id": "evalset-v1",
  "kind": "calibration",
  "frozen_at": "2026-01-14T00:00:00Z",
  "description": "812 C functions from 11 embedded TLS and protocol libraries, labelled by two reviewers independently, disagreements resolved by a third. 34 CVE-confirmed positives.",
  "size": 812,
  "base_rate": 0.042,
  "operating_points": [
    { "name": "strict", "threshold": 0.90, "fpr": 0.021, "recall": 0.41 },
    { "name": "loose",  "threshold": 0.55, "fpr": 0.118, "recall": 0.79 }
  ]
}
```

| field | meaning |
|---|---|
| `id` | must equal the filename without `.json`, and must be what the backend's `calibration` names after `calibrated@`. A bare name - letters, digits, `.`, `_`, `-` - never a path: an id holding `/`, `..` or an absolute path is refused, because the registry is this directory and nothing outside it. A file whose `id` disagrees with its name is refused rather than matched by path, because the two would then diverge silently |
| `kind` | `"calibration"`, literally. It is what separates a calibration from everything else this directory holds - see below |
| `frozen_at` | ISO-8601. **Must predate the run** — `score_functions.py` compares it against `run.json.started_at` |
| `description` | what is in it, who labelled it, and how disagreements were settled. Prose, read by a person deciding whether to believe a number |
| `size` | number of labelled functions, at least 1 |
| `base_rate` | share of them labelled vulnerable, a number strictly between 0 and 1. A threshold's false-positive rate is unreadable without it, so `null` is refused |
| `operating_points` | the measured points, at least one. Each has a `threshold` in [0, 1], and `fpr` and `recall` each `null` or in [0, 1]. `fpr` and `recall` are **copied** onto `operating-point.json` when a run selects by `mode: "score"` at a matching `threshold`, and are `null` otherwise |

### Not everything here is a calibration

`baseline-2026-09.json` freezes a POPULATION, and says so with `"kind": "population"`:
which advisories were reached and ranked through stage 3, with `base_rate: null`
and `operating_points: []`, because it measures no false-positive
rate. It is what `ledger.py export` reads for `postdates_eval_freeze`, and it is
refused as a calibration: its kind is not `"calibration"`, and it has nothing
measured for a probability to mean. Binding a backend's `evalset_id` to it
downgrades the run with `no_evalset`. `score_functions.py` ignores fields beyond
the seven above.

`fpr_claim` and `recall_claim` in `operating-point.json` come from this file or
they do not exist. Nothing computes them from the run — a rate measured on the
corpus it was chosen for is not a rate, and the pipeline has no labels for the
tree it is scanning anyway. A `top_k` or `top_percent` selection carries no claim
at all, whatever is registered here, because a rank cut is not a threshold.

## Why it has to be frozen, and frozen first

`ledger.py export` turns confirmations and rejections into training samples. The
moment that starts, every later measurement is measuring a model on data its own
feedback loop produced. An evaluation set frozen **before** the ledger began is
the only thing that can tell improvement from memorisation — which is why
`samples.jsonl` carries `postdates_eval_freeze`, computed against the
`frozen_at` in this directory, so a training run can exclude everything the loop
touched.

So the order is: freeze the set, record it here, then start the flywheel. Doing
it the other way produces a number that goes up and means nothing.

Three rules follow, and two of them are enforced in code:

1. **Never edit a registered file.** Fixing a label changes what every past run
   claimed. Register `evalset-v2.json` and move the backend's `evalset_id`.
2. **Never register a set frozen after a run it is used to judge.** Enforced:
   `frozen_at` must predate `run.json.started_at`, or the run downgrades with
   `evalset_not_frozen`.
3. **Never point a backend at a set measured on a different context profile.**
   Enforced from the other side: the backend declares the profile it was trained
   on, and a corpus extracted under another one — or under that profile's name
   with a different `--budget-tokens` — downgrades with
   `context_profile_mismatch`. A calibration does not survive a change of window.

## What registering one does not do

Registering a file here does not make a score calibrated; it records that
somebody measured one. Two further gates still apply to every run
(pipeline-contract §6), and neither has an override flag:

- more than 10% of the corpus arriving as `window` records rather than parsed
  functions downgrades the run (`window_share_exceeded`) — the classifier was
  not trained on ranges that are not functions — and so do records whose
  confidence is none of the three values, which leave that share unmeasurable
  (`confidence_unrecorded`);
- a `context.profile` that is not the backend's `trained_context_profile`, or a
  context budget that is not the one that profile defines, downgrades it
  (`context_profile_mismatch`).

Every downgrade lands in `scores/scorer-report.json` with a code and a sentence,
and `REPORT.md` carries those sentences. A reader who is not told the score is an
ordering will read it as a probability, and that is the failure this whole
directory exists to prevent.
