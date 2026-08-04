# Independent benchmark — XSS Grenade vs Google Firing Range

## Why this exists

The in-repo benchmark (`../benchmark_scoreboard.py`) scores **18/18 recall, 0 false
positives**. That number is close to meaningless as evidence of quality, because
*this project wrote the corpus*. A scanner and a test suite authored by the same
hand will agree with each other; that demonstrates self-consistency, not
capability.

This benchmark fixes the two things that made the internal one unfalsifiable:

| | internal corpus | this benchmark |
|---|---|---|
| who wrote the test pages | this project | Google (used verbatim) |
| who decided "vulnerable" | this project | a real Chromium |

## Design

**Corpus — Google Firing Range, verbatim.**
[Firing Range](https://github.com/google/firing-range) is a purpose-built XSS
scanner benchmark from Google's security team. The page templates under
`templates/` are copied unmodified (Apache-2.0, see `LICENSE.firing-range`).
Firing Range is a Java/AppEngine app and there is no JVM here, so `fr_server.py`
is a mechanical 1:1 port of the handful of servlets that generate the XSS
corpus — the Java behaviour it preserves is documented in that file and pinned
by `../test_v10_85_firingrange_bench.py`.

311 endpoints in three families:

| family | count | what it is |
|---|---|---|
| `reflected` | 37 | a parameter reflected raw into 37 different HTML/JS/CSS contexts |
| `escaped` | 148 | the same 37 contexts × 4 **deliberately partial** escapers |
| `address` | 126 | 9 URL-derived DOM sources × 14 DOM sinks |

The `escaped` family is the interesting one. Google's `Escaper.java` provides
escapers that each neutralise *one* character (`"`, `'`, `>`) plus a full HTML
escaper. So `DOUBLE_QUOTED_ATTRIBUTE` is genuinely safe inside `attr="…"` and
genuinely **unsafe** inside `attr='…'` or in body text. A scanner that pattern-
matches "output is escaped → safe" fails on recall; one that ignores escaping
fails on precision. There is no way to score well on both without actually
modelling context.

**Ground truth — measured, not asserted.**

> An endpoint is VULNERABLE ⟺ a real Chromium executed attacker JS on it.

`fr_oracle.py` fires a fixed battery of ~30 public XSS vectors (OWASP / PortSwigger
cheat-sheet shapes) at every endpoint, identically — no per-context tailoring —
and watches for a JS dialog carrying a canary. It also synthesises user
interaction (click/mouseover on every element), because much of the corpus is
event-handler based. Whatever the browser did not execute is labelled SAFE, and
a scanner flagging it at actionable severity is counted as a false positive.

This matters more than it sounds. Labelling by reasoning would have been wrong:
see "Chromium URL encoding" below.

## Running it

```bash
python fr_oracle.py                    # build ground truth (~20 min, drives Chromium)
python benchmark_firingrange.py        # HTTP-level detection
python benchmark_firingrange.py --deep # + Chromium (DOM v6 + headless verify)
```

`fr_server.py` can also be run standalone (`python fr_server.py 8781`) to point
the GUI at the corpus.

## Scoring

Reported under two conventions so the headline cannot be cherry-picked:

- **LENIENT** — recall counts *any* finding on the endpoint; a false positive
  requires `>= high` severity without `fp_risk`. (This is the convention the
  internal benchmark already used: an `info` note is not crying wolf.)
- **STRICT** — both sides thresholded at `>= high` without `fp_risk`; i.e. what
  a user actually reads as "this is a vulnerability".

## Two findings about the *method* worth keeping

Both of these would have silently corrupted the result, and both were caught
only by validating the oracle against known-answer cases before trusting it.

**1. Fragment-only navigation does not reload.** Driving the browser from
`…/x#payloadA` to `…/x#payloadB` is a *same-document* navigation — page scripts
never re-run. Every hash-sourced DOM sink looked inert. Fixed by resetting to
`about:blank` between probes.

**2. `location.hash` / `location.search` hand JS *undecoded* text.** A fully
percent-encoded payload arrives at the sink as the literal string
`%3Cimg%20src%3Dx…` and is harmless. Real DOM XSS is delivered raw. The oracle
now encodes only what would break the URL structure.

**Chromium URL encoding — why much of `address/` is labelled safe.** Chromium
percent-encodes `<`, `>` and space in the fragment and query. Firing Range's
templates do *not* call `decodeURIComponent`. So `location.hash → innerHTML`,
the textbook DOM XSS, **does not fire** in Chromium 148 with a markup payload —
only sinks that eval the value as JS (`eval`, `setTimeout`, `javascript:` href)
execute. Had ground truth been assigned by textbook reasoning, ~100 endpoints
would have been mislabelled vulnerable and the scanner charged with false
negatives it did not commit.

The honest reading: a *static* finding on `location.hash → innerHTML` is still
defensible — the pattern is dangerous and one `decodeURIComponent` anywhere
makes it live — it simply is not browser-exploitable as written. That is why the
`address` family is scored and reported **separately** rather than folded into
one headline number.
