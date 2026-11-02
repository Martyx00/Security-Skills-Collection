#!/usr/bin/env python3
"""
scorers - the backend registry for stage 2.

A backend is a class registered here by name, and selecting one is a `backend`
key in the --config file or a `--backend` flag. That is the whole adoption cost
of the fine-tuned classifier when it lands: nothing else in the pipeline reads
the backend's name, and nothing downstream of scores.jsonl knows which one ran.

Registering by name in one dict, rather than by scanning the directory, is
deliberate. A backend that appears because somebody dropped a file in here is a
backend nobody reviewed, and `--backend` would then accept a name that has never
been held against contract §6.

Stdlib only. Python 3.8+.
"""

from .base import Backend, BackendError, HandshakePending  # noqa: F401
from .finetuned_backend import FinetunedBackend
from .llm_triage_backend import LlmTriageBackend
from .rules_backend import RulesBackend

BACKENDS = {
    RulesBackend.name: RulesBackend,
    LlmTriageBackend.name: LlmTriageBackend,
    FinetunedBackend.name: FinetunedBackend,
}

# llm-triage, not rules. The rules backend produces a bare ordering, and on a
# real tree rules@1.0.0 made that ordering a 245-function tie at the top score -
# an operating point chosen from it is a slice of a coin flip. llm-triage draws
# BANDS the model actually committed to, and on the same tree it put two
# known-vulnerable functions at ranks 1 and 3 of 6,196 where rules@1.0.0 had
# them tied with 243 others. Both are rules@1.0.0 measurements: llm-triage
# orders inside each band by the rules score, so rules@1.1.0 reorders inside
# its bands too.
#
# It is not free, and unlike stage 4 its cost is linear in the WHOLE corpus
# rather than in the cut: ~1,153 tokens per function measured, and with each
# worker's own reading on top, ~3.3M input tokens in all on a 778-function tree
# and ~24M on a 6,196-function one, paid before the operator sees anything:
# ~$2.50-$5 and ~$17-$39 at the reference prices llm_triage_backend quotes (this
# skill carries no per-model prices, and some hosts bill in credits). The
# handshake states the figure, and whose prices it used, before the first call,
# which is what keeps the default honest rather than merely convenient. `rules`
# stays one flag away and costs nothing.
DEFAULT_BACKEND = LlmTriageBackend.name


def backend_names():
    return sorted(BACKENDS)


def get_backend(name):
    """The class registered under `name`, or KeyError naming what exists."""
    try:
        return BACKENDS[name]
    except KeyError:
        raise KeyError("no scoring backend %r; known backends: %s"
                       % (name, ", ".join(backend_names())))
