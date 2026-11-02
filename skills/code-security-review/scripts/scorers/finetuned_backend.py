#!/usr/bin/env python3
"""
finetuned_backend.py - the seam. The fine-tuned function-level classifier does
not exist yet; this is the code that will read it, written and tested now.

The reason it is written before the model is the reason the whole bundle is
shaped the way it is. A backend added later, under the pressure of finally
having a trained classifier to show, is a backend written past the refusals in
pipeline-contract §6 - and §6 is the only thing standing between "0.94" and a
report that calls it a 94% chance. Written now, against a stub HTTP server in
the selftest, the refusals are load-bearing before there is any incentive to
route around them.

It speaks OpenAI-compatible `POST /v1/completions` with `logprobs`, which vLLM,
TGI and llama-server all serve, over urllib.request. No `requests`, no client
library: a scanner that cannot run on a machine with nothing but python3 is a
scanner that does not run where the code is.

HOW THE NUMBER IS DERIVED. The model is asked for one token. The response's
top-logprobs are read for the two verdict tokens the model was trained to emit,
and the score is the two-way softmax over them:

    p = exp(lp_pos) / (exp(lp_pos) + exp(lp_neg)) = 1 / (1 + exp(lp_neg - lp_pos))

which is the sigmoid of the margin, written in the form that does not overflow.
Everything else in the distribution is ignored - deliberately: a model that
spends mass on a third token is a model answering a different question, and
renormalising over two tokens says so honestly rather than hiding it.

WHAT IT IS ALLOWED TO CLAIM. This is the ONE backend that may declare
`score_kind: "probability"`, and it declares it only when its config names an
evaluation set. It does not get to decide whether it keeps it:
score_functions.py checks that the set is registered under
assets/evalsets/, that its `frozen_at` predates the run, that the
corpus's context profile is the one the config says the model was trained on,
and that fewer than 10% of the corpus came back as windows rather than parsed
functions. Any of those failing downgrades the score to an ordering and records
the reason. There is no flag that relaxes it.

CONFIG (see security-review/scorers.example.json):

    endpoint          base URL, with or without /v1/completions
    model             the model name sent to the server, verbatim
    api_key_env       env var holding the bearer token, or null
    verdict_tokens    {"positive": "vulnerable", "negative": "safe"} - the exact
                      token strings the model was trained to emit
    context_profile   the profile the model was trained under
    evalset_id        the frozen evaluation set that calibrated it, or null
    batch_size        prompts per HTTP request (the endpoint takes a list)
    timeout           seconds per request
    max_retries       retries on 5xx, 429, connection failure and a response
                      cut off mid-body; 0 disables them
    retry_backoff_seconds, logprobs
                      the first retry's wait, and the top-k asked for

An absent numeric setting takes its default; one that is present and is not a
number in range is refused, naming the key - `max_retries: 0` used to become 2.

A redirect is refused, never followed. urllib copies every header but the body's
onto the next request, the bearer token included, whatever host or scheme the
Location names - and a redirected POST comes back as a GET, which cannot return
completions anyway. Point `endpoint` at the final URL.

Stdlib only. Python 3.8+.
"""

import http.client
import ipaddress
import json
import math
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from . import base

RETRY_STATUS = (408, 409, 425, 429, 500, 502, 503, 504)


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    """Follow nothing. Returning None hands the 3xx to the default error handler,
    which raises it as an HTTPError before any second request is made."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# key -> (default, integral, floor, floor is exclusive, what is accepted). The
# defaults are the ones scorers.example.json documents.
SETTINGS = {
    "batch_size": (8, True, 1, False, "a whole number of at least 1"),
    "timeout": (60.0, False, 0, True, "a number of seconds above 0"),
    "max_retries": (2, True, 0, False, "a whole number of at least 0, and 0 "
                                        "disables retries"),
    "retry_backoff_seconds": (0.5, False, 0, False, "a number of seconds of at "
                                                     "least 0"),
    "logprobs": (20, True, 2, False, "a whole number of at least 2, because a "
                                     "top-1 can never carry both verdict tokens"),
}


def _setting(cfg, key):
    """A numeric config value: its default when absent, refused when it is not one."""
    default, integral, floor, exclusive, accepted = SETTINGS[key]
    value = cfg.get(key)
    if value is None:
        return default
    try:
        ok = (isinstance(value, (int, float)) and not isinstance(value, bool)
              and math.isfinite(value)
              and (not integral or float(value).is_integer())
              and (value > floor if exclusive else value >= floor))
    except OverflowError:
        # A JSON integer too large for a float: isfinite() raises rather than
        # answering, and that is a refusal too, not a traceback.
        ok = False
    if not ok:
        raise base.BackendError(
            "scorer config for backend 'finetuned': %s is %r, and it must be %s. "
            "See security-review/scorers.example.json." % (key, value, accepted))
    return int(value) if integral else float(value)


def _logprob(value):
    """A logprob the server sent, as a float, or ValueError when it is not one.

    -inf is a real answer (probability zero); null, a string or NaN is not, and
    float() on them either raised a TypeError past every handler or - for NaN -
    produced a margin that silently scored 0.0.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("logprob %r is not a number" % (value,))
    try:
        value = float(value)
    except OverflowError:
        # An integer too large for a float is no logprob either, and
        # OverflowError is not a ValueError: it escaped _score_one's handler.
        raise ValueError("logprob is an integer too large to be a float")
    if math.isnan(value):
        raise ValueError("logprob is NaN")
    return value


def _loopback(url):
    host = urllib.parse.urlsplit(url or "").hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


DEFAULT_PROMPT = """\
### FILE: {{FILE}}
### FUNCTION: {{NAME}} ({{LANGUAGE}}), lines {{LINE_START}}-{{LINE_END}}
### SIGNATURE: {{SIGNATURE}}
### RULE HITS:
{{RULE_HITS}}
### CODE:
{{CONTEXT}}
### VULNERABLE:"""


class FinetunedBackend(base.Backend):

    name = "finetuned"
    version = "1.0.0"
    score_kind = base.KIND_ORDINAL      # raised to probability by config, below
    calibration = None
    trained_context_profile = None
    requires_explanations = False

    thread_safe = True                  # one independent HTTP call per batch
    rank_normalised = False             # the number is already in [0,1]
    requires_context_text = True

    def __init__(self, config=None):
        base.Backend.__init__(self, config)
        cfg = self.config
        self.endpoint = _completions_url(cfg.get("endpoint"))
        self.model = cfg.get("model")
        self.api_key_env = cfg.get("api_key_env")
        tokens = cfg.get("verdict_tokens") or {}
        if isinstance(tokens, (list, tuple)) and len(tokens) == 2:
            tokens = {"positive": tokens[0], "negative": tokens[1]}
        self.positive = tokens.get("positive")
        self.negative = tokens.get("negative")
        self.trained_context_profile = cfg.get("context_profile")
        self.evalset_id = cfg.get("evalset_id") or None
        # `cfg.get(k) or default` turned an explicit 0 into the default: an
        # operator who wrote max_retries: 0 got three requests per batch.
        self.batch_size = _setting(cfg, "batch_size")
        self.timeout = _setting(cfg, "timeout")
        self.max_retries = _setting(cfg, "max_retries")
        self.backoff = _setting(cfg, "retry_backoff_seconds")
        self.top_logprobs = _setting(cfg, "logprobs")
        self.template = cfg.get("prompt_template") or DEFAULT_PROMPT

        # A backend that names an evaluation set is CLAIMING calibration. §6
        # decides whether it keeps it; it is not asked twice and cannot insist.
        if self.evalset_id:
            self.score_kind = base.KIND_PROBABILITY
            self.calibration = "calibrated@%s" % self.evalset_id

        self._auth = None
        self._index = {}
        self._context = {}
        self._opener = urllib.request.build_opener(_RefuseRedirect)
        self.requests_made = 0
        self.bounded = 0                # items where one verdict token was absent

    def model_name(self):
        return self.model

    def cache_fingerprint(self):
        # What moves the number: which server, which checkpoint, which two
        # tokens are read, the text they are read after, and how deep the top-k
        # goes (a token outside it takes the bounded path). Timeouts, retries,
        # batch size and the key's variable name do not.
        return base.fingerprint({"endpoint": self.endpoint, "model": self.model,
                                 "verdict_tokens": [self.positive, self.negative],
                                 "prompt_template": self.template,
                                 "logprobs": self.top_logprobs})

    # -- lifecycle ---------------------------------------------------------- #

    def prepare(self, functions, rule_hits, config):
        """Everything checkable without the endpoint, checked before the first call.

        A missing key or a typo'd token name fails at request time otherwise -
        which on an 18,000-function corpus means after the first few thousand
        have been paid for.
        """
        missing = [k for k, v in (("endpoint", self.endpoint), ("model", self.model),
                                  ("verdict_tokens.positive", self.positive),
                                  ("verdict_tokens.negative", self.negative))
                   if not v]
        if missing:
            raise base.BackendError(
                "scorer config for backend 'finetuned' is missing %s. See "
                "security-review/scorers.example.json." % ", ".join(missing))
        if self.positive == self.negative:
            raise base.BackendError(
                "scorer config: verdict_tokens.positive and .negative are both %r; "
                "a softmax over one token is 1.0 for every function"
                % self.positive)
        if self.api_key_env:
            key = os.environ.get(self.api_key_env)
            if not key:
                raise base.BackendError(
                    "scorer config names api_key_env %s, which is not set in this "
                    "environment. An unauthenticated request to %s fails at the "
                    "first batch, not here." % (self.api_key_env, self.endpoint))
            self._auth = "Bearer %s" % key
            if (urllib.parse.urlsplit(self.endpoint).scheme == "http"
                    and not _loopback(self.endpoint)):
                # A note, not a refusal: plain http inside a private network is
                # a real deployment. It must not pass silently, though.
                self.notes.append(
                    "%s is plain http to a host that is not this machine, so the "
                    "key in %s travels in cleartext on every request"
                    % (self.endpoint, self.api_key_env))
        if not self.trained_context_profile:
            # Not fatal: §6 turns it into a downgrade rather than a stop, because
            # an uncalibrated ordering from an untrained-profile window is still
            # an ordering. It must not pass silently, though.
            self.notes.append(
                "no context_profile in the scorer config, so the backend cannot "
                "claim it was trained on this run's window")

        self._index = base.index_hits(rule_hits)
        self._context = (config.get("_run") or {}).get("context_text") or {}

    def score_batch(self, items):
        results = []
        for start in range(0, len(items), self.batch_size):
            chunk = items[start:start + self.batch_size]
            prompts = [self._prompt(item) for item in chunk]
            choices = self._complete(prompts, chunk[0]["function"])
            for item, choice in zip(chunk, choices):
                results.append(self._score_one(item, choice))
        return results

    def close(self):
        if self.bounded:
            self.notes.append(
                "%d function(s) came back without one of the two verdict tokens in "
                "the top-%d logprobs; the absent token was bounded at the smallest "
                "logprob returned, so those scores are an upper bound on the margin "
                "rather than a reading of it"
                % (self.bounded, self.top_logprobs))
        self.notes.append("%d request(s) to %s" % (self.requests_made, self.endpoint))

    # -- the prompt --------------------------------------------------------- #

    def _prompt(self, item):
        fn = item["function"]
        hits = base.hits_for(fn, self._index)
        hit_text = "\n".join(
            "%s %s:%s %s" % (h.get("rule_id"), h.get("file"), h.get("line"),
                             (h.get("sink_text") or "").strip())
            for h in sorted(hits, key=lambda h: (h.get("line") or 0,
                                                 str(h.get("rule_id"))))) or "none"
        context = item.get("context_text")
        if context is None:
            context = self._context.get(fn["function_id"], "")
        text = self.template
        for token, value in (("{{FILE}}", fn.get("file")),
                             ("{{NAME}}", fn.get("name")),
                             ("{{LANGUAGE}}", fn.get("language")),
                             ("{{SIGNATURE}}", fn.get("signature") or ""),
                             ("{{LINE_START}}", fn.get("line_start")),
                             ("{{LINE_END}}", fn.get("line_end")),
                             ("{{RULE_HITS}}", hit_text),
                             ("{{CONTEXT}}", context)):
            # Token replacement rather than str.format: a C function full of
            # braces is not a format string, and treating it as one raises
            # KeyError on the first `struct { int x; }` in the corpus.
            text = text.replace(token, "" if value is None else str(value))
        return text

    # -- the call ----------------------------------------------------------- #

    def _complete(self, prompts, sample_function):
        body = {
            "model": self.model,
            "prompt": prompts,
            "max_tokens": 1,
            "temperature": 0.0,
            "logprobs": self.top_logprobs,
            "echo": False,
        }
        data = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._auth:
            headers["Authorization"] = self._auth
        where = "%s:%s" % (sample_function.get("file"),
                           sample_function.get("line_start"))

        last = None
        for attempt in range(self.max_retries + 1):
            request = urllib.request.Request(self.endpoint, data=data,
                                             headers=headers, method="POST")
            try:
                self.requests_made += 1
                with self._opener.open(request, timeout=self.timeout) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as exc:
                detail = _body(exc)
                if 300 <= exc.code < 400:
                    raise base.BackendError(
                        "%s: %s answered HTTP %s with a redirect to %s, and "
                        "redirects are refused: following one sends the bearer "
                        "token wherever it points, and a redirected POST cannot "
                        "return completions. Set `endpoint` to the final URL."
                        % (where, self.endpoint, exc.code,
                           (exc.headers or {}).get("Location") or "(no Location)"))
                if exc.code not in RETRY_STATUS:
                    raise base.BackendError(
                        "%s: %s returned HTTP %s for a batch of %d: %s"
                        % (where, self.endpoint, exc.code, len(prompts), detail))
                last = "HTTP %s: %s" % (exc.code, detail)
            except urllib.error.URLError as exc:
                last = str(exc.reason)
            except (ValueError, OSError, http.client.HTTPException) as exc:
                # HTTPException: a connection dropped mid-body (IncompleteRead) is
                # neither an OSError nor a URLError, and escaped as a traceback
                # without a single retry.
                last = "%s: %s" % (type(exc).__name__, exc)
            if attempt < self.max_retries:
                time.sleep(self.backoff * (2 ** attempt))
        else:
            raise base.BackendError(
                "%s: %s failed %d time(s) for a batch of %d; last error: %s"
                % (where, self.endpoint, self.max_retries + 1, len(prompts), last))

        if not isinstance(payload, dict):
            raise base.BackendError(
                "%s: %s returned a JSON %s, not an object, for a batch of %d"
                % (where, self.endpoint, type(payload).__name__, len(prompts)))
        choices = payload.get("choices")
        if not isinstance(choices, list) or len(choices) != len(prompts):
            raise base.BackendError(
                "%s: %s returned %s choices for %d prompts. A response that does "
                "not line up with the batch would score functions against other "
                "functions' answers."
                % (where, self.endpoint,
                   len(choices) if isinstance(choices, list) else "no", len(prompts)))
        # `index` is authoritative when the server sends it; order is the fallback.
        if all(isinstance(c, dict) and isinstance(c.get("index"), int) for c in choices):
            choices = sorted(choices, key=lambda c: c["index"])
        return choices

    def _score_one(self, item, choice):
        fn = item["function"]
        where = "%s:%s" % (fn.get("file"), fn.get("line_start"))
        try:
            table = _top_logprobs(choice)
        except (TypeError, ValueError) as exc:
            # Refused rather than skipped: dropping the entry would send the
            # function down the bounded path and hide a server fault as a score.
            raise base.BackendError("%s: %s returned a non-numeric logprob for %s: %s"
                                    % (where, self.endpoint, fn.get("function_id"), exc))
        if not table:
            raise base.BackendError(
                "%s: %s returned no logprobs for %s. The endpoint must be called "
                "with `logprobs` and must return them; without the distribution "
                "there is no score, and a default here would be a made-up one."
                % (where, self.endpoint, fn.get("function_id")))

        lp_pos = _lookup(table, self.positive)
        lp_neg = _lookup(table, self.negative)
        if lp_pos is None and lp_neg is None:
            raise base.BackendError(
                "%s: neither verdict token (%r, %r) appears in the top-%d logprobs "
                "for %s. The tokens returned were: %s. Check verdict_tokens against "
                "what the model was trained to emit."
                % (where, self.positive, self.negative, self.top_logprobs,
                   fn.get("function_id"),
                   ", ".join(repr(t) for t in sorted(table)[:8])))
        if lp_pos is None or lp_neg is None:
            # One token fell outside the returned top-k. Its true logprob is at
            # most the smallest one returned, so bound it there: the margin is
            # then an upper bound rather than a guess, and close() counts how
            # many scores came out of that bound.
            floor = min(table.values())
            self.bounded += 1
            if lp_pos is None:
                lp_pos = floor
            else:
                lp_neg = floor

        margin = lp_pos - lp_neg
        if math.isnan(margin):
            # Both tokens at -inf: no margin exists, and `margin > -700` being
            # False for NaN used to turn that into a silent 0.0.
            raise base.BackendError(
                "%s: %s gave both verdict tokens (%r, %r) a logprob of -inf for %s, "
                "so there is no margin to read a score from"
                % (where, self.endpoint, self.positive, self.negative,
                   fn.get("function_id")))
        score = 1.0 / (1.0 + math.exp(-margin)) if margin > -700 else 0.0

        hits = base.hits_for(fn, self._index)
        hit = base.top_hit(hits)
        line = (hit or {}).get("line")
        lo, hi = fn.get("line_start"), fn.get("line_end")
        if not isinstance(line, int) or not (isinstance(lo, int) and isinstance(hi, int)
                                             and lo <= line <= hi):
            # The classifier says how suspicious, not where. Localisation comes
            # from the rule hit, and when there is no hit it is null rather than
            # the function's first line - a plausible wrong line is worse than
            # none, because stage 3 joins analyzer findings within +/-3 of it.
            line = None
        return {
            "score": score,
            "raw_score": margin,
            "weakness_class": (hit or {}).get("cwe"),
            "localized_line": line,
            "explanation": None,
        }


# --------------------------------------------------------------------------- #
# response shapes
# --------------------------------------------------------------------------- #

def _top_logprobs(choice):
    """token -> logprob for the first generated token, across the served shapes.

    vLLM and llama-server answer the legacy completions shape
    (`logprobs.top_logprobs[0]`, a dict); some servers answer the chat shape
    (`logprobs.content[0].top_logprobs`, a list of {token, logprob}). Both are
    read, because which one is in front of this backend is a deployment detail
    nobody will remember to configure.
    """
    if not isinstance(choice, dict):
        return {}
    lp = choice.get("logprobs")
    if not isinstance(lp, dict):
        return {}
    top = lp.get("top_logprobs")
    if isinstance(top, list) and top and isinstance(top[0], dict):
        return dict((str(k), _logprob(v)) for k, v in top[0].items())
    content = lp.get("content")
    if isinstance(content, list) and content and isinstance(content[0], dict):
        entries = content[0].get("top_logprobs")
        if isinstance(entries, list):
            return dict((str(e.get("token")), _logprob(e.get("logprob")))
                        for e in entries if isinstance(e, dict)
                        and e.get("token") is not None)
    return {}


def _lookup(table, token):
    """Find a verdict token's logprob, tolerating the leading-space convention.

    BPE tokenizers emit " vulnerable" where the training data had "vulnerable",
    and a config written from the training script says the latter. Matching only
    exactly turns every score into the bounded path.
    """
    for candidate in (token, " " + token, "Ġ" + token, token.strip()):
        if candidate in table:
            return table[candidate]
    stripped = dict((k.strip(), v) for k, v in table.items())
    return stripped.get(token.strip())


def _completions_url(endpoint):
    if not endpoint:
        return None
    url = str(endpoint).rstrip("/")
    if url.endswith("/v1/completions"):
        return url
    if url.endswith("/v1"):
        return url + "/completions"
    return url + "/v1/completions"


def _body(exc):
    try:
        text = exc.read().decode("utf-8", "replace").strip()
    except Exception:                             # noqa: BLE001
        return "(no body)"
    return text[:300] or "(empty body)"
