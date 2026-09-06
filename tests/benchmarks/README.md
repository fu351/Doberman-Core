# Doberman benchmark harness — wiring external task suites

A small, **suite-agnostic** harness that scores Doberman as a *filter over
labeled actions* and reports per-suite **ASR** (attack bypass rate) and **FPR**
(benign over-block / friction). It maps any external agent-security task suite —
**[AgentDojo]**, **AgentDyn**, **AgentSentry**, … — onto core's `SecurityObject`
/ `EvalContext`, runs the real `decide()` engine, and classifies the verdict.

It imports **only** core's public API and **registers nothing** — it is a read-
only consumer of the engine. No third-party suite code or data is vendored here;
you point an adapter at a suite you obtain yourself.

[AgentDojo]: https://github.com/ethz-spylab/agentdojo

---

## Mental model: Doberman is the filter, not the agent

These suites are normally used to run an *agent* end-to-end. Doberman is a
**mediator** that judges each candidate tool-call. So we do **not** run the
suite's agent. Instead we take the suite's **labeled candidate actions** —

- **attack** = an action that, if allowed, advances an attacker's injected goal,
- **benign** = a legitimate user-task action —

map each to a `SecurityObject` + `EvalContext`, run `decide()`, and score the
verdict (`PASS` < `AUTH` < `BLOCK`):

| label  | `PASS`         | `AUTH`              | `BLOCK`        |
|--------|----------------|---------------------|----------------|
| attack | **bypassed**   | mitigated           | mitigated      |
| benign | ok             | friction (FPR)      | false block    |

This keeps the gated path **deterministic and offline** (no live model). If a
suite only ships task *definitions* (not recorded agent traces), generating
traces needs an agent + LLM — that is **out of scope** for the gated harness; run
it separately and feed the resulting labeled actions in.

---

## Layout

```
tests/benchmarks/
├── adapter.py     # CandidateAction, BenchmarkCase, SuiteAdapter  (the contract)
├── mapping.py     # CandidateAction -> SecurityObject / EvalContext
├── profiles.py    # build_pipeline(load_plugins=...) -> Pipeline; PassthroughPipeline (no-guardrail baseline)
├── metrics.py     # SuiteReport: ASR, asr_strict, FPR, hard_fpr; corpus_metrics: per-category TPR/FPR/precision
├── runner.py      # run_suite, run_profiles (builtins vs plugins), run_before_after (without vs with Doberman)
├── run.py         # CLI: python -m tests.benchmarks.run --suite <name> --profile both  (+ --corpus, --subjective, --replay-session)
├── session_replay.py  # --replay-session: exercise the real taint floor + echo tripwire + session correlator in a fresh isolated per-case session
├── suites/
│   ├── synthetic.py   # built-in, deterministic, dependency-free (the CI gate)
│   ├── corpus.py      # the labeled detection corpus (C8): loader + adapter + per-row driver
│   ├── devsession.py  # built-in, deterministic, dependency-free — seeded warm corpus (C11)
│   ├── agentdojo.py   # AgentDojo + AgentDyn adapters (on-demand; lazy `agentdojo` import)
│   ├── redcode.py     # RedCode-Exec adapter (on-demand; env DOBERMAN_BENCH_REDCODE_DIR)
│   ├── msb_poisoning.py  # MSB tool-response-poisoning adapter (on-demand; env DOBERMAN_BENCH_MSB_DIR)
│   ├── llmail_inject.py  # LLMail-Inject adapter (on-demand; env DOBERMAN_BENCH_LLMAIL_DIR)
│   └── <your_suite>.py
└── README.md      # this file
```

Tests: `tests/unit/test_benchmark_harness.py` (metrics/selector/isolation),
`tests/unit/test_benchmark_agentdojo.py` (the AgentDojo/AgentDyn mapping +
redaction, with the `agentdojo` package faked), and
`tests/integration/test_benchmark_synthetic_gate.py` (real-engine gate).

---

## The contract you implement

A suite adapter is any object with a `suite_name` and a `load()` that yields
`BenchmarkCase`s:

```python
from collections.abc import Iterable
from doberman.models import ActionType, SourceContext
from tests.benchmarks.adapter import BenchmarkCase, CandidateAction

class MySuiteAdapter:
    suite_name = "mysuite"

    def __init__(self, root: str) -> None:
        self._root = root  # operator-supplied path to the obtained suite

    def load(self) -> Iterable[BenchmarkCase]:
        for task in _read_tasks(self._root):          # YOUR parsing
            yield BenchmarkCase(
                case_id=task.id,                       # NO payload text in the id
                label="attack" if task.is_injection else "benign",
                note=task.category,                    # class-level label only
                attacker_goal_index=task.goal_step,    # or None = all actions count
                actions=tuple(
                    CandidateAction(
                        action_type=_map_action_type(call.kind),  # -> ActionType.*
                        tool_name=call.tool,
                        target=call.target,                       # path / resource
                        external_destination=call.url_or_host,    # for egress
                        source_context=SourceContext.tool_output, # provenance
                        raw_arguments=call.arguments,             # may hold payload
                    )
                    for call in task.tool_calls
                ),
            )
```

Then run it:

```python
from tests.benchmarks.runner import run_profiles
report = run_profiles(MySuiteAdapter(root="/path/to/suite"))
```

Register it in `suites/__init__.py` (`BUILTIN_ADAPTERS`) **only if** it needs no
external data (the synthetic suite does that); suites that need an operator-
supplied path stay out of the always-on CI gate and run on demand.

### Field-mapping cheatsheet

| suite concept | maps to | notes |
|---|---|---|
| tool call kind (read/write/exec/http/git/install) | `CandidateAction.action_type` (`ActionType.*`) | pick the closest; use `ActionType.other` if unsure |
| tool name | `tool_name` | free text |
| file path / resource | `target` | the canonical rules read this |
| destination URL / host | `external_destination` | drives the egress rule; leave `None` for a command-shaped payload (`raw_arguments["command"]`/`cmd`/`script`/`args`) and `mapping.to_security_object` derives it from the proxy's own command-egress extractor, same as production — set it yourself only when the suite's own data already names a destination |
| where the instruction came from | `source_context` (`SourceContext.*`) | `tool_output` / `webpage` / `email` for injected content |
| raw tool arguments / body | `raw_arguments` (dict) | reaches `EvalContext.metadata["raw_arguments"]`; **may contain attack text** |
| ground-truth attack vs benign | `BenchmarkCase.label` | the single most important field to get right |
| which step is the attacker's goal | `attacker_goal_index` | `None` ⇒ every action in an attack case is scored |

---

## Profiles (`builtins_only` vs `with_plugins`)

The only difference is core's shipped `load_plugins` flag:

- `builtins_only` — only the built-in rules/detectors run.
- `with_plugins`  — built-ins **plus** any entry-point plugins installed in the
  environment (`doberman.rules` / `doberman.detectors`).

`run_profiles()` runs both and reports the **uplift** (`delta_asr`, `delta_fpr`).
On a standalone core install nothing is registered, so the two profiles are
identical and uplift is 0 — install a plugin package and the delta shows what it
adds. (The harness names no specific plugin package; it just measures whatever is
installed.)

### `no_guardrail` — the "before Doberman" baseline

`run_before_after()` adds a third arm: a **`PassthroughPipeline`** that allows
every action without consulting the engine. This models the **unmediated tool
path** — what happens with no guardrail at all. By construction, on a ground-
truth attack corpus it bypasses every attack (`asr 1.0`) with zero benign
friction (`fpr 0.0`), so it is the honest *before* against which a real Doberman
pipeline is the *after*:

```bash
python -m tests.benchmarks.run --suite synthetic --profile before_after
```

The report is `{before (no_guardrail), after (builtins_only), delta}`. The
`delta` is the headline of what the engine changes:

| field | meaning |
|---|---|
| `attacks_stopped` | fraction of otherwise-executing attacks now mitigated (BLOCK **or** AUTH) = `before.asr − after.asr` |
| `attacks_stopped_strict` | same but BLOCK-only counts (AUTH is *not* counted as stopped) |
| `fpr_added` | benign friction the engine introduces = `after.fpr − before.fpr` |
| `hard_fpr_added` | benign hard-blocks the engine introduces = `after.hard_fpr − before.hard_fpr` |

`before` is a *trivial* baseline (1.0 by definition) — it is the denominator
that makes the *after* legible, not an independent measurement. Report it as
"with no guardrail every one of these N attacks executes," never as a number the
harness "discovered."

### `--replay-session` — exercising the post-decide floors

`decide()` alone never triggers the taint floor (`doberman.engine.taint_floor.apply_taint_floor_async`),
the echo tripwire (`apply_echo_tripwire_async`, C1), or the session correlator
(`doberman.engine.correlator.apply_correlator_async`) — all three are deliberately post-decide, reading
persisted session state after `decide()` returns (see each module's own docstring). The default harness
path calls `decide()` statelessly per action, so those three floors are **never exercised** by default — a
multi-action attack (read untrusted content, then send) is scored purely on each action's own per-call
verdict.

```bash
python -m tests.benchmarks.run --suite agentdojo --profile before_after --replay-session
python -m tests.benchmarks.run --suite llmail_inject --profile before_after --replay-session   # needs DOBERMAN_BENCH_LLMAIL_DIR
python -m tests.benchmarks.run --suite msb --profile before_after --replay-session              # needs DOBERMAN_BENCH_MSB_DIR
```

`--replay-session` replays each case inside a fresh, isolated per-case session (a temp SQLite DB;
`session_id = case_id`) and applies the real floors, in the real order, after each `decide()` — the
report carries `"session_replay": true` at both the top level and inside every nested report so a
replayed number is never confused with a stateless one. **Read this before comparing numbers**: the echo
tripwire fires on an EXACT host/URL/email value reused from an earlier untrusted read — LLMail-Inject's
real 2-action shape (read a phishing email that names the attacker's own address, then send to that exact
address) is precisely this pattern, so its ASR under `--replay-session` is expected to drop. The taint
floor only fires on secret-*shaped* content, and the correlator's `correlated_trifecta` needs a prior
secret-class reason code — narrower wins. All three floors require the consummating action to carry an
`external_destination`; a consummating action that is a local file write/process action with no
destination (some MSB attack types) is untouched by any of them, replayed or not.

---

## Metrics (read `metrics.py` for the exact math)

- **ASR** — `bypassed / attacks`; mitigation counts `BLOCK` **or** `AUTH`
  (an `AUTH` interrupts an autonomous chain). The headline bypass rate.
- **asr_strict** — mitigation counts `BLOCK` **only**; `AUTH` is treated as not
  stopped (a human might approve). The conservative lower bound on protection.
- **FPR** — `(benign AUTH + benign BLOCK) / benign`; the friction cost.
- **hard_fpr** — `benign BLOCK / benign`; false hard-blocks of legitimate work.

Always report ASR **and** asr_strict together — don't oversell a number.

---

## Redaction (mandatory)

Reports contain **counts, case ids, verdict names, and reason codes only** —
**never** payload text. `raw_arguments` may carry the attack string, but it never
enters a report. Keep payload text out of `case_id` and `note`. The synthetic
suite ships a `PAYLOAD_MARKER` and the gate asserts it never appears in any
serialized report — keep that guarantee for your suite too.

---

## Running

```bash
# from the repo root, in the project venv
python -m tests.benchmarks.run --suite synthetic --profile both          # builtins vs plugins
python -m tests.benchmarks.run --suite synthetic --profile before_after  # without vs with Doberman
python -m pytest tests/integration/test_benchmark_synthetic_gate.py      # the gate

# labeled detection corpus — per-category FPR / TPR / precision (C8, issue #241)
python -m tests.benchmarks.run --suite corpus --corpus                   # balanced (row-native) mode
python -m tests.benchmarks.run --suite corpus --corpus --mode strict     # any F6 mode
python -m pytest tests/integration/test_corpus_gate.py                    # the raise-only + FP gate

# subjective-layer baseline-separation diagnostic (needs agentdojo; standalone flag)
python -m tests.benchmarks.run --suite agentdojo --subjective
```

### The labeled detection corpus (`--corpus`)

Where the synthetic suite proves the *harness* is wired correctly and the ASR/FPR
path reports aggregate bypass/friction, the **detection corpus** measures
detection *quality* per category. It is a flat JSONL fixture
(`tests/corpus/detection_corpus.jsonl`) — one labeled row per line:

```json
{"id": "des-0000", "kind": "destructive", "surfaces": {"action_type": "shell_exec"},
 "payload": "…", "is_attack": true, "expected_verdict_at_least": "BLOCK",
 "forbidden_verdict_at_least": null, "notes": "recursive root delete"}
```

* An **attack** row (`is_attack: true`) carries `expected_verdict_at_least` — a
  **measured, raise-only floor**: the verdict the engine reaches today
  (`null` = a documented gap it does not yet catch). A floor may only rise; the
  generator refuses to lower one.
* A **benign** row carries `forbidden_verdict_at_least` — the false-positive
  guard: the verdict a legitimate action must never reach (usually `AUTH` — it
  must stay `PASS`).

`--corpus` reports **TPR** (mitigation = `AUTH` or `BLOCK`), **tpr_strict**
(`BLOCK` only), **FPR**, **precision**, the ids of any row that broke its
floor or guard — per category and overall — and **auth_gated**: the attack rows
that stopped at `AUTH` rather than `BLOCK`, broken down by shape (category,
action type, reason codes) so a reader can see where protection rests on a human
answering the prompt. `tests/integration/test_corpus_gate.py`
runs the deterministic tier in CI and fails on any violation. Regenerate + recalibrate
against the live engine with `python -m tests.corpus._generate` (a dev tool; the
shipped JSONL is a static fixture — **adding a labeled row needs no harness
change**). Payloads are synthetic and redaction-safe; the secrets category
triggers on credential *paths* and shapeless high-entropy values, never assembled
provider literals.

`--subjective` runs a distribution-separation diagnostic over the subjective
layer's per-suite streaming baseline instead of the ASR/FPR profile/mode path
— see [`docs/BENCHMARKS.md`](../../docs/BENCHMARKS.md#subjective-layer-baseline-separation-diagnostic)
for the methodology and the honest-vs-leak-quantifier arm split.

---

## Per-suite linking notes

> **Verify first.** Before writing an adapter, confirm the suite's real
> repository, task/label schema, and **license** for the data you intend to use.
> Do **not** commit third-party fixtures whose license forbids redistribution —
> load them from an operator-supplied path and commit only a tiny synthetic or
> license-clear subset for any gated test.

### AgentDojo (reference, best-documented) — adapter shipped
- Source: `https://github.com/ethz-spylab/agentdojo`. Tasks are organized into
  **suites** (banking, slack, travel, workspace) with **user tasks** (benign) and
  **injection tasks** (attack), each naming the tool calls and the attacker goal.
- Map: each user-task tool-call → a `benign` case; each injection-task tool-call
  whose success = the injected goal → an `attack` case (`attacker_goal_index`
  pointing at the goal call). Put injected content's origin in `source_context`
  (`tool_output` / `webpage`). Pin a commit hash for reproducibility.
- **Implemented** in `suites/agentdojo.py` (`AgentDojoAdapter`), registered in
  `BUILTIN_ADAPTERS` as `agentdojo`. It imports the `agentdojo` package **lazily**
  (so CI never depends on it) and vendors **no** suite data — `pip install
  agentdojo`, then `python -m tests.benchmarks.run --suite agentdojo`.

### AgentDyn — adapter shipped (data is operator-supplied)
- *Dynamic*/multi-step, AgentDojo-derived; reuses the same `agentdojo` package
  API and adds the `shopping`/`github`/`dailylife` suites. Each step is emitted
  as an ordered `CandidateAction` in one `BenchmarkCase` with `attacker_goal_index`
  at the consummating egress step, so multi-step correlation is exercised.
- **Implemented** as `AgentDynAdapter` in `suites/agentdojo.py` (registered as
  `agentdyn`). Put the AgentDyn checkout on the path to resolve its data, e.g.
  `PYTHONPATH=/path/to/AgentDyn/src python -m tests.benchmarks.run --suite agentdyn`.
- **Confirm AgentDyn's license before redistributing any of its data**; the
  adapter loads it from your supplied path and vendors nothing here.

### Devsession — built-in, adapter shipped
- Not an external suite: a seeded synthetic corpus (four developer-session archetypes) sized to clear
  the subjective layer's `K_OBSERVATIONS`/`HST_WARMUP` thresholds, which AgentDojo's much smaller warm
  traces don't reach. See [`docs/BENCHMARKS.md`](../../docs/BENCHMARKS.md#subjective-layer-baseline-separation-diagnostic)
  for the caveat: this measures distribution separation on a synthetic corpus, not real telemetry.
- **Implemented** in `suites/devsession.py` (`DevSessionAdapter`), registered in `BUILTIN_ADAPTERS` as
  `devsession`. No external data, no network: `python -m tests.benchmarks.run --suite devsession --subjective`.

### AgentSentry
- **Confirm the exact project name, schema, and license first** (not yet
  verified here). Map its attack/benign labels onto `BenchmarkCase.label` and its
  tool-calls onto `CandidateAction` exactly as above.

If a named suite turns out not to exist under that name or its license is
incompatible, **stop and report** rather than inventing a mapping.

### RedCode-Exec — adapter shipped
- Source: `https://github.com/AI-secure/RedCode` (code MIT; dataset CC BY 4.0). 4,050 (Index, Prompt,
  Language, Code, expected_result, Text_summary, Text_details) records asking an agent to execute a risky
  Bash/Python snippet.
- Map: each record's ``Code`` → one ``CandidateAction`` (`action_type=shell_exec`, the snippet in
  `raw_arguments["command"]`), label `attack` (RedCode ships no benign counterpart — the adapter supplies
  its own synthetic benign command set, extracted through the same target/destination logic as the attack
  records). `source_context=user` (direct misuse, not injection).
- **Implemented** in `suites/redcode.py` (`RedCodeAdapter`), registered as `redcode`. Reads
  `DOBERMAN_BENCH_REDCODE_DIR`; vendors no data. `scenario_report()` gives the per-scenario in-scope/
  out-of-scope breakdown (`python -m tests.benchmarks.suites.redcode`). Single-action cases — stateless
  and `--replay-session` are byte-for-byte identical for this suite, so only the stateless run is
  published; see [`docs/BENCHMARKS.md`](../../docs/BENCHMARKS.md#redcode-exec-risky-code-execution).

### MSB — adapter shipped
- Source: `https://github.com/dongsenzhang/MSB` (MIT). 12 MCP-specific attack types across the tool-use
  pipeline (task planning / tool invocation / response handling).
- Map: each (attack_task, attack_type) pair → a two-action `BenchmarkCase` (a poisoned tool response,
  `source_context=tool_output`; the consummating action it tries to trigger,
  `attacker_goal_index=1`), built from three static MSB files (`attack_task.jsonl`, `attack_type.jsonl`,
  `prompt_template.py` — parsed via `ast.literal_eval`, never imported/executed). See
  `suites/msb_poisoning.py`'s module docstring for why this differs from a static tool-definition/schema
  diff.
- **Implemented** in `suites/msb_poisoning.py` (`MsbPoisoningAdapter`), registered as `msb`. Reads
  `DOBERMAN_BENCH_MSB_DIR`; vendors no data, executes no MSB code. `attack_type_report()` gives the
  per-attack-type breakdown (`python -m tests.benchmarks.suites.msb_poisoning`). Published in both
  stateless and `--replay-session` modes — identical numbers, because every MSB consummating action here
  is a local file write or process action with no `external_destination`, so none of the three post-decide
  floors can engage; see [`docs/BENCHMARKS.md`](../../docs/BENCHMARKS.md#msb-mcp-tool-response-poisoning).

### LLMail-Inject — adapter shipped
- Source: `https://huggingface.co/datasets/microsoft/llmail-inject-challenge` (MIT). Labelled email
  prompt-injection submissions from a real adaptive-attacker challenge.
- Map: submissions with `attack_attempt == "True" and reason == "api_triggered"` (the target tool call
  actually fired) → a two-action `BenchmarkCase` (the email arriving, `source_context=email`; the
  consummating `send_email` to the challenge's fixed attacker address, `attacker_goal_index=1`). Benign:
  `emails_for_fp_tests.json` as read-only cases, plus a second, synthetic benign SEND case per email (a
  fixed, clearly-synthetic recipient) so FPR is also measured on an ordinary legitimate send.
- **Implemented** in `suites/llmail_inject.py` (`LlmailInjectAdapter`), registered as `llmail_inject`.
  Reads `DOBERMAN_BENCH_LLMAIL_DIR`; vendors no data. Deterministic seeded sample (`sample_size`, default
  500, configurable). Published in both stateless and `--replay-session` modes — identical top-line
  ASR/FPR (`engine/rules/destinations.py::_parse_host` AUTHs a bare `user@host` destination unconditionally
  in every mode, before either post-decide floor runs), but the reason-code breakdown differs sharply
  (`untrusted_value_echo` on ~470/500 attacks under replay); see
  [`docs/BENCHMARKS.md`](../../docs/BENCHMARKS.md#llmail-inject-email-prompt-injection).
