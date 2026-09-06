# Known limitations

Doberman blocks and flags actions using deterministic rules, not a general threat model. Every rule
below catches one specific kind of attack, and every rule has some specific way around it. This page
lists the gaps I know about today, in plain language, so you know exactly what Doberman does and
does not catch. None of them break the raise-only guarantee (Doberman can tighten a rule
automatically, but a change never silently loosens what was already blocked or flagged) or the
fail-closed guarantee (an error or an unhandled case denies the action, it never lets it through).
They are places the deterministic rule engine has no signal yet, not places the engine gets talked
out of its own decision.

## Spoofed-word detection catches mixed-script fakes, not single-script ones

A homoglyph is a letter from one alphabet that looks like a letter from another, for example a
Cyrillic letter that looks like a Latin one. A confusable is a word built from homoglyphs to imitate
a real word, like `раypal` for `paypal`. Doberman's `mixed_script_confusable` check catches a
confusable that mixes two alphabets in one word.

A newer `whole_script_confusable` check catches the harder case: a word written entirely in one
non-Latin alphabet that still looks like a Latin word, such as an all-Cyrillic look-alike of
`paypal`. That word survives Unicode normalization (NFKC, the step that would otherwise collapse
look-alike characters to one form), and no other channel catches it, so this one has to. Both checks
are raise-only: they can only add friction, never remove it.

The whole-script check only knows a small, hand-picked set of Cyrillic and Greek letters that
closely resemble Latin ones. A word that uses even one letter outside that set slips past both
checks. Closing the rest of this gap needs a model-agnostic detector based on perplexity (how
surprising a string of text looks to a language model) or general confusable detection; that work
is tracked as issue #234.

## Hash-shaped and ID-shaped secrets can slip past the general secret detector

A high-entropy string (one where the characters look close to random, a common trait of a real
secret key) usually gets flagged. But git commit hashes, content digests, AST (abstract syntax tree,
a parsed structure of source code) digests, MD5 checksums, and UUIDs are also high-entropy, and
flagging every one of them was the single biggest source of false positives (an alert on something
that was never actually a problem) in this check. It was bad enough to poison the taint ledger too
(the record Doberman keeps of which values came from an untrusted read, so it can catch them again
if they get sent out).

So the heuristic now ignores a token if it is *entirely* shaped like a hash (32 or more hex
characters) or a dashed UUID. That means a real secret with no other giveaway, one that happens to
be plain hex or UUID-shaped with no `API_KEY=`-style name next to it, is not caught by this check
alone. It is still caught if it carries a credential key name (like `API_KEY=`), matches a known
credential shape, or later gets matched by the read-vs-send fingerprint (a value Doberman saw in an
untrusted read that then shows up again in something being sent out). One side effect: lowering the
length floor from 40 to 32 characters also lets a bare 128-bit hex value slip through this
particular check; the stronger credential-shape check is not affected.

## Ordinary identifiers, paths, and version-like tags are now exempt from the weak entropy check, at a small, measured cost

Shannon entropy (a standard measure of how many different characters a string uses, not how random
it actually is) treats an ordinary variable name, a relative file path, or a build tag like `py311`
or `x86` the same as a short base64-encoded (a common way to encode binary data as text) secret.
Both land in the same 3.6 to 4.5 bits per character range, and this used to trigger a false
`possible_high_entropy_secret` alert about six times for every one real hit, the kind of alert
fatigue that trains people to click approve without reading.

Now a token is exempt from this check only if every piece of it, once split on separators, is an
ordinary word, a number, a short capped `word+number` combination (like `py311`), or a hash/UUID-shaped
id. A long base64 or JWT (JSON Web Token, a common format for auth tokens) segment fails that test,
so the whole token still gets judged, and a secret can't be broken into small exempt pieces to dodge
the length floor.

The one measured cost: for a bare base64url secret with no key name and no known prefix next to it,
the chance that every one of its segments happens to look exempt rises from about 0.8% to 3.6% at 24
characters, 0.2% to 0.9% at 32 characters, and 0.01% to 0.1% at 43 characters. The stronger
credential-shape check is unaffected either way.

On an egress path (anything leaving the machine over the network), this exemption is withheld for a
token made only of joined words, because a passphrase looks the same shape, but it is kept for a
token containing a `/`, since a filesystem path, URL path, or git ref is not a passphrase. That
distinction is what keeps every `gh api` call and every branch reference from prompting for approval
on a push.

## The large-blob detector catches bulk data dumps by shape, not by content, and can be evaded by splitting the payload

`Base64BlobDetector` steps a command up to `AUTH` (require approval) when one of its arguments is a
large base64-looking blob, and it tolerates the line-wrapping the PEM and MIME formats use. It never
decodes the data. It only looks at shape and size, and it's built to catch a bulk file or secret
dump, not a small credential (a separate rule handles those).

An attacker can dodge it by splitting the payload across several calls or arguments that each stay
under the size threshold, mixing in characters outside the base64 alphabet, or switching to a
different encoding. Like every rule here, this is raise-only friction (`AUTH`), never a guarantee.

## Test-fixture and example-pattern text is quietly excused from the weak entropy check only, and only after checking what's left over

A bare token (not part of an `x = ...` assignment) that is really regex source being quoted, like
`sk-ant-[A-Za-z0-9_-]{20,}`, or an obvious hand-written test fixture, is not flagged by the
high-entropy heuristic alone (issue #73).

A fixture marker word (`EXAMPLE`, `SAMPLE`, `FAKE`, `DUMMY`) or an ordered filler like `0123...` or
`abcd...` is something an attacker could type too, and for a secret with no other identifying shape,
the entropy heuristic is the only signal Doberman has. So a marker word alone is not trusted:
Doberman strips the marker words and any ordered filler runs, then checks what's left. Only if that
leftover text is too short or too low-entropy to be a real secret does the check stay quiet. A real
key padded with the word `EXAMPLE` still has a high-entropy leftover and still fires. Naming a
variable with a marker word (like `EXAMPLE_KEY = ...`) never suppresses its value either, because the
check runs on the right-hand side of the `=`, not the variable name.

This suppression never touches the strong credential-shape check, which can still trigger a
`secret_exfiltration` result. Regex source characters (`[`, `]`, `{`, `}`, `\`) are suppressed
unconditionally, because Doberman's own tokenizer can never produce them from a real secret. A full,
realistic-looking example key quoted in prose with no marker word at all still looks exactly like a
real one, and still gets flagged.

## Egress classification reads command text; it does not yet control the actual network connection

Egress means any traffic leaving your machine over the network. Doberman now looks for an external
destination not just in `network_request` calls, but also in shell, package-manager, and git
commands. It recognizes two kinds of egress verbs: HTTP and file-copy tools (`curl`, `wget`, `scp`,
`sftp`, `rsync`) and raw socket or remote-shell tools (`nc`, `ncat`, `netcat`, `ssh`, `telnet`,
`ftp`, `tftp`, `socat`). Piping a secret into `curl <host>` or `nc host port` is a hard `BLOCK`. Any
other egress command, including one aimed at a trusted-looking host, or one whose destination can't
be pinned down to a single route (a bare `nc host port` or an `ssh -R` tunnel with no URL), steps up
to `AUTH` (require approval). This check is raise-only: it never grants a new silent allow, and
anything ambiguous fails toward asking a human.

But this is a *static* check: it reads the command's text and can say "this looks like egress," but
it cannot prove the host it read is the actual socket the process opens. Several things still route
around it: a redirect file, curl's `--resolve`/`--connect-to` flags, an
`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` environment override, DNS rebinding (a name resolving to a
different address at connection time than it did at classification time), a URL built at runtime, a
`git push` to an already-configured remote, a package's install-time lifecycle script, a trusted
service used as a relay, or egress launched from a spawned child process.

Channels that don't use a recognizable command verb are mostly uncovered. DNS-label exfiltration
(encoding stolen data into subdomain names and leaking it through `dig`, `host`, or `nslookup` TXT
lookups) shows no destination or verb this classifier recognizes; catching it needs an entropy or
n-gram (a way of scoring text by how likely its short character sequences are) heuristic Doberman
doesn't have yet. Bash's built-in `/dev/tcp` and `/dev/udp` redirections, and `openssl s_client`, are
caught by a separate, narrower check described in the next entry, but this classifier still can't
resolve or route-check them.

Real containment needs a runtime egress broker: something that watches or controls the actual
connection, not just the command text proposing it. The building blocks for one now exist in core,
unregistered by default (opt-in only, through the `doberman.egress_brokers` entry point, a Python
packaging mechanism other packages use to register a plugin without Doberman needing to import them
by name):

- An `EgressBroker` interface that Doberman consults on every egress-classified action.
- A registered broker can report what an entity's connections actually did a moment ago. That
  retrospective signal can raise a decision toward `AUTH` when it disagrees with the static
  classification, but it can never lower a decision or grant a `PASS` on its own.
- A reference broker implementation: a default-deny allowlist, a two-sided test that a direct
  connection must fail while a broker-routed one must succeed, and a real listener, a minimal HTTP
  `CONNECT` forward proxy (`doberman.egress.proxy.ForwardProxy`, built only on Python's standard
  library) that enforces the allowlist at the socket, so a blocked destination's connection is never
  opened. It only supports the `CONNECT` method (no SOCKS), and it has no way to transparently
  intercept traffic that isn't explicitly routed to it.
- The destination check (`ExternalDestinationRule`) can hand out `PASS` instead of its usual `AUTH`,
  but only when the broker reports itself as `PROVEN` to enforce egress, and its verdict both
  allowlists the destination and reports `will_enforce` for this exact destination at the socket. An
  unproven or non-enforcing broker's allowlist claim still leaves the result at `AUTH`, and a
  detected route mismatch always overrides a broker's `PASS`.
- Paranoid mode can escalate a non-allowlisted destination all the way to a hard `BLOCK`, but only
  under that same proven, enforcing-broker condition, so the escalation is never just a mode toggle
  pretending to enforce something it doesn't. With no broker registered, Paranoid mode behaves like
  every other mode here.
- A registered broker's connection history also feeds a bounded, in-memory check per entity for
  bursts, high volume, or fanning out to many destinations in the same recent window. That check can
  raise a `PASS` to `AUTH`, even overriding a broker-granted `PASS`, or add a reason to an
  already-`AUTH`/`BLOCK` result. It never lowers a decision, and it says nothing when there is no
  broker registered or the broker reports no connection history.

## Raw-socket shell tricks are caught by shape, and only step up to AUTH except for one shape that BLOCKs

`DestructiveCommandRule` (the same rule that blocks catastrophic commands like `rm -rf /`)
recognizes four ways a shell command can open a raw network socket directly (the `raw_socket_channel` check): a `/dev/tcp` or
`/dev/udp` redirection, `netcat`/`ncat`/`socat` used to wire a socket straight to command execution
(a reverse or bind shell), `openssl s_client`, and an inline Python or Node one-liner that opens a
socket itself.

Of those, the exec-on-connect shapes, a socket wired to running a command (`nc -e`, `--sh-exec`,
socat's `EXEC:` or `SYSTEM:`, or an inline payload that both opens a socket and spawns a subprocess
or shell), are unambiguous reverse or bind shells, and those now `BLOCK`. The other three shapes (a
bare `/dev/tcp` redirect, `openssl s_client`, a bare inline socket with no subprocess) only step up
to `AUTH`.

This only recognizes these specific flag and token shapes. Reaching the same tool through a full
path (`/usr/bin/nc`), a differently named build, or assembling a reverse shell at runtime with string
concatenation, `getattr`, or a base64-decoded module name, is not caught. An inline `python -c` or
`node -e` payload containing a bare `connect(` call steps up to `AUTH` (reason code
`opaque_command`) even when the call opens no socket at all, for example `sqlite3.connect(...)`.
That's a deliberate false positive (an alert on something harmless): the shape check can't tell a
database handle from a network one, and Doberman would rather over-flag than miss one.

The segment splitter shared by every static command rule in this module can now see through shell
keywords (`if ... then ... fi`, `for ... do ... done`, `case ... esac`), brace groups (`{ ...; }`),
subshells (`(...)`), and function bodies (`name() { ...; }`, `function name { ...; }`), to find the
real command nested inside. A command assembled at runtime from variables is still invisible to it.

DNS-label exfiltration (`dig`, `nslookup`, `host` with a data-bearing subdomain) is deliberately out
of scope here too: telling an encoded payload apart from a legitimate long hostname needs an entropy
or n-gram heuristic with no calibration behind it yet, and this is the single highest false-positive
risk item this slice chose not to ship.

`DestructiveCommandRule` also now recognizes process-kill and signal commands: `kill`, `pkill`,
`killall`, `taskkill`, PowerShell's `Stop-Process`/`spps`, `xargs` piping into any of those, and an
interpreter one-liner calling `os.kill`, `os.killpg`, `process.kill`, or the `psutil` library's
`.kill()`/`.terminate()`. An agent that could only `rm -rf` a file under a prompt injection, but
could kill the operator's database, IDE, or CI runner with no check at all, was a real gap regardless
of any benchmark score. These step up to `AUTH`, never `BLOCK`. A signal aimed at the user's own job
(`%1`, `%%`, `$!`, `$$`) or a probe/list/help flag (`-l`, `-L`, `-0`, `-n 0`, `-s 0`, `--signal=0`,
`--help`) stays `PASS`, but only when that flag is the only option present. Combined with any other
option, for example `kill -0 -9 <pid>` or `kill -s 0 -s KILL <pid>`, it's treated as a real signal,
since which `kill` implementation is running is unknown, and some read the extra flag as a second
signal. Reaching a kill command through `sudo`, a `for` loop, or aiming it at any other process id,
does not stay `PASS`.

An inline interpreter payload (`python -c`/`node -e`) that spawns a subprocess (via `subprocess`,
`os.system`, `child_process`, and similar) is now stepped up too, and the same rule walks the
command-line strings or list literals it hands to that subprocess, so a catastrophic command inside
still raises the step-up all the way to `BLOCK`. A command assembled at runtime inside that payload,
through string concatenation or a variable, is still opaque to this check.

An inline payload broken into more than 128 candidate pieces (split on whitespace, quotes, brackets,
or punctuation) steps up to `AUTH` (`opaque_command`), because it's too fragmented to fully check.
That's a length proxy, not real content analysis: an ordinary one-liner measures 7 to 43 pieces, so
this leaves a wide margin, and the 128-piece cap is a floor applied after every stronger check runs,
never a shortcut around them. A control-plane, destructive, socket, kill, or privilege match found in
the same payload still wins and still `BLOCK`s or `AUTH`s at its own severity, no matter how
fragmented the payload is.

A wrapper command's own flags are now consumed instead of being misread as the wrapped command
itself (see the wrapper entry below), and `su -c`, `su - <user> -c`, and `su <user> --command=` are
treated as opaque exactly like `bash -c`, walking their payload the same way.

A nested `$(...)` command substitution now tracks its own quoting independently of any string it
sits inside, so a stray quote deep inside a nested substitution can no longer swallow a trailing
command past where that substitution actually ends. An unterminated `$(` now fails upward to `AUTH`
instead of being silently accepted, and the text it would have swallowed is still checked for an
embedded destructive command.

## Downloaded-file integrity checking happens after the download, and only for files you've pinned in advance

A `network_request` action gets its `PASS` before the fetch actually happens. The `ForwardProxy`
broker described above is an HTTP `CONNECT` proxy that relays encrypted (TLS) traffic without
decrypting it, so it never sees the actual response bytes and can't check a payload before deciding
whether to allow the request. Verifying content ahead of time would require intercepting and
decrypting that traffic, which is deliberately out of scope here.

Instead, Doberman checks integrity after the fact, at the same point where it already scans output
for leaked secrets, once the downstream tool call has returned. It hashes the fetched result text
with SHA-256 (a standard way to produce a short fingerprint of a file's exact contents) and compares
that fingerprint against any pin you've configured in `.doberman/artifact_pins.yaml`. A mismatch
withholds the content from the agent; a match lets it through.

Any artifact with no configured pin is not verified at all. This is a narrow, explicit-allowlist
check, not a general supply-chain guarantee, and if you have no pins file, this feature changes
nothing about how Doberman behaves.

## Common command wrappers (`sudo`, `nice`, `timeout`, and similar) used to hide the real command from Doberman; now they don't, with one narrow exception

A wrapper like `sudo -u www-data curl ...`, `nice -n 10 curl ...`, or `timeout 5 curl ...` shifts
where the real command sits in the argument list (argv). Every static rule used to read the
wrapper's own option as if it were the command, and missed what came after it.

The shared command-parsing helper now recognizes each of these wrappers' own value-taking options
and skips past them before looking for the wrapped command: `sudo`, `doas`, `runuser`, `env`,
`nice`, `ionice`, `timeout`, `chroot`, `time`, `exec`, `stdbuf`, `nohup`, `command`, `setsid`,
`builtin`, `strace`, `taskset`, `flock`, and `unshare`. It chains through nested wrappers too, for
example `sudo -n nice -n 5 rm -rf /`. `runuser -c`/`--command`/`--command=` and `flock -c`/
`--command` are treated as opaque, exactly like `su -c`: their payload is walked the same way, never
treated as an option to skip past.

Now that the wrapped command is recovered, a wrapped `rm -rf /` gets `BLOCK`ed and a wrapped secret
exfiltration attempt gets the same verdict as its unwrapped form. That closes what used to be a real
bypass, and it's raise-only: it never creates a new silent allow.

There's one deliberate exception that goes the other way. A command segment whose real verb was only
found by skipping past a wrapper option (not just a bare wrapper name with no options) never
qualifies for the implied-registry `PASS` that an ordinary default-route package fetch can otherwise
get. That's because options like `sudo -H`, `sudo -u <user>`, or `nice -n 10` change exactly the
thing (the home directory, or the user the command runs as) that decides which config file the
fetch's registry route resolves against. That shape stays at the `egress_requires_auth` `AUTH`
result it already had.

When the skipping itself can't fully resolve, for example `env -S <value>` where the value doesn't
split cleanly into shell tokens, the leftover option or value tokens are never read as the command
either. A command segment whose first word is still an unresolved option after wrapper stripping
steps up to `AUTH` (`opaque_command`) instead of silently passing through.

Before this fix, `strace`, `flock`, `unshare`, and `taskset` were exactly that kind of unrecognized
wrapper, and the actual result was worse than the ambiguous-egress `AUTH` this document used to claim:
none of the four was on the wrapper list at all, so the shared helper didn't even try to skip past
their options. It read the wrapper's own name as the command verb, found no destructive pattern and
no known egress tool there, and let the whole line through. `strace -f rm -rf /`, `flock /tmp/lock
rm -rf /`, `taskset -c 0 rm -rf /`, and `unshare -n curl http://evil.example/x` were each a silent
`PASS`, hiding the wrapped command entirely rather than stepping up to `AUTH`. All four are now on
the recognized-wrapper list above and classify the same as their unwrapped form.

The honest remaining gap: a wrapper outside that list still shifts the argument list in a way
Doberman doesn't recognize, so its wrapped command isn't seen at all, the same silent-`PASS` failure
mode these four just came out of, not the `AUTH` step-up this section previously (and incorrectly)
described.

## Behavior-learning checks only run on the MCP proxy path today, not on the Claude Code or OpenClaw hooks

Those two hosts' hooks run Doberman's deterministic rules only (path confinement,
destructive-command detection, secret patterns, egress classification, role boundaries, the
enforcement dial). They don't consult the adaptive layer (`doberman.subjective`): the per-entity
behavioral baseline (what a normal action for this agent or repo usually looks like), the score for
how surprising a new action is compared to that baseline, or drift detection (a pattern of behavior
sliding away from the baseline over time).

That's deliberate. A `PreToolUse` hook (Claude Code's term for a hook that runs before a tool call
executes) runs before every single tool call, and importing `numpy`, `scipy`, and `river` (the
libraries the adaptive layer needs) at that point costs about two seconds per call. Both hooks now
share one evaluate-and-record code path, so a verdict can't drift between hosts just because of
which host is running it.

The hook path still gives you every deterministic guardrail. Adaptive escalation, the part that
learns and reacts to unusual behavior, currently needs the MCP proxy. Wiring the adaptive layer onto
the hook path through a warm background process is planned.

## A tripwire for reused untrusted values matches exact text only, and only from two tools

If a `WebFetch` or `WebSearch` result contains a host, URL, or email address, and something Doberman
sees later tries to send data to that exact value, the decision steps up from `PASS` to `AUTH`. This
is exact matching, using a keyed HMAC (a cryptographic fingerprint made with a secret key, so two
identical values always produce the same fingerprint without storing the original value), not an
analysis of how data actually flows through the agent's reasoning. A value that gets rephrased,
partially reused, or that first appeared through some other untrusted channel Doberman doesn't watch
here, such as an issue or PR body read a different way, or a different MCP tool's result, is not
caught by this signal.

The same exact-value design also produces a specific kind of false positive: any host mentioned
anywhere in an untrusted result, even one with no connection to that content's actual instructions,
steps up once the first time any later call contacts it, as long as it isn't already on the trusted
allowlist or named by the user in their own message. Trusted-allowlist hosts are matched the same way
`ExternalDestinationRule` matches them, by registered-domain suffix, so a subdomain of a trusted host
is excluded too, and this exclusion applies whether the host appears bare or inside a full URL.

This signal is capped at `AUTH` in every mode; it never causes a hard `BLOCK` on its own. It's also
bounded in scope and time: 5,000 values per scope, with a 7-day expiry, unlike the secret ledger,
which keeps entries indefinitely. On the hook path, scope means one real per-invocation session id;
on the MCP proxy path, which has no session id of its own, scope means the repository entity for the
duration of that expiry window.

One more interaction worth knowing: recording an untrusted read also marks that scope as tainted,
with `TAINT_UNTRUSTED_READ`. Doberman's five-minute exact-repeat approval memory
(`doberman.auth.challenge`, which normally lets you re-approve an identical action within five
minutes with one click) refuses to apply inside any tainted scope. So once a session has read
anything untrusted, approval memory stops working there for every later `AUTH`, not only ones
involving the echoed value, and the same action, or any other `AUTH`, prompts again every time.
That's fail-closed by design.

This is also a fix specific to the MCP proxy path: `record_output_taint` used to drop the tool name
entirely, so the proxy never recorded any `TAINT_UNTRUSTED_READ` taint no matter what it fetched, and
approval memory kept quietly applying after an untrusted read. That gap is now closed, so the proxy
path taints correctly, the way the hook path always did.

Email addresses are matched after undoing common obfuscation like `[at]` and `(dot)` or extra
spacing, so `user [at] host [dot] com` fingerprints the same as `user@host.com`. This
de-obfuscation is mechanical pattern-matching, not an understanding of meaning: a sentence like "ask
Bob at example . com" can occasionally be read as an address and fingerprinted the same as
`bob@example.com`, even though it never actually named one. The only consequence of that false match
is one extra `AUTH` prompt if a later call happens to send to that exact synthesized address; it
never causes a silent allow.

## Doberman recognizes specific environment-dump commands by name, not every way to print environment variables

Running `env`, `printenv`, `export` or `export -p`, `declare -x` or `typeset -x`, or PowerShell's
`Env:` drive listing steps up to `AUTH` before it runs.

Left out on purpose: a bare POSIX `set` (which lists shell variables and functions both, but is also
extremely common as `set -e` or `set -euo pipefail` at the top of ordinary scripts, so flagging it
bare would cause a lot of false alarms for a vector that's rarely actually abused), and a bare
Windows `cmd.exe` `set` for the same reason.

A literal trailing backslash, as in `dir env:\`, isn't in this rule's list of Windows path triggers,
so the command fails Doberman's normal shell-argument parsing before this check even runs, and falls
back to the generic `opaque_command` `AUTH` instead. It still fails upward toward requiring approval,
just tagged with a different reason. The no-backslash form, `dir env:`, is unaffected.

Like every rule that classifies static command text, this can't see what a program's *output*
actually contains. A Python one-liner with no recognizable command name that reads `os.environ`
internally and prints it isn't caught here; only the scan that runs on a program's output after it
executes would catch that.

## Doberman protects its own configuration from the agent it's watching, but not from a human at the keyboard

Whenever an action routes through the decision engine, a write, delete, or read of Doberman's own
state directory (`.doberman/`) or a host's hook-and-trust configuration is hard-blocked. The same
check catches a shell command that merely names one of those paths, so `rm -rf .doberman` or
`echo > .claude/settings.json` gets caught too.

This protected set also covers the Codex CLI's control plane: `.codex/hooks.json`,
`.codex/config.toml`, and the `.codex/` plugin directories are hard-blocked, and the rest of
`.codex/**` steps up to `AUTH`, mirroring how `.claude/` and `.doberman/` are treated. That
protection applies the moment a Codex action reaches the decision engine.

But which actions actually reach the engine depends on the front door. Today that covers Claude Code
(through its hooks) and any tool server wrapped by the MCP proxy. A Codex CLI `PreToolUse` adapter
now exists too (`doberman hook codex-pre`; Codex's hook layer is a compatibility shim for Claude
Code's, so it shares the same decision logic and denial format), and `doberman install-hooks --host
codex` wires it into `~/.codex/hooks.json`, or a project-local copy with `--local`, in one command.

Even with that wired up, the limit is honest: this stops the *agent* from disabling its own
oversight, not a *human*. Someone at the keyboard can always disable a hook directly, for example
with Codex's own `--dangerously-bypass-hook-trust` flag. And a control-plane path built at runtime,
from a shell variable, a glob pattern, or a `python -c` payload, isn't caught by this kind of static
command-text check.

## An optional AI judge exists for measurement only, not for live decisions

Installing `pip install "doberman-core[judge]"`, setting an `ANTHROPIC_API_KEY`, and setting
`DOBERMAN_JUDGE_ENABLED=1` enables `doberman.judge.HaikuJudgeAdjudicator`, a second-opinion
classifier. It sees only a redacted, class-only summary (`redacted_features()`, the same limited
envelope the shadow-adjudicator design allows: no path, command, argument, or secret is ever
included).

Nothing in Doberman's core registers or calls this judge during a real decision. The only place it
runs today is an offline replay, `tests/benchmarks/suites/judge_agreement.py`, over the labeled
benchmark corpus, measuring whether adding a language model improves on the deterministic rules
working from that same limited summary. See [`BENCHMARKS.md`](BENCHMARKS.md).

Wiring any judge into a live decision would need its own design decision. Doberman's raise-only
guarantee (an automatic change can only tighten a rule, never loosen it) governs which *direction* a
verdict can move, not whether the system becomes dependent on a network call to an outside model,
and that step hasn't been taken.

## Checks that catch someone silencing tests or CI are based on command shape and file path only, not on what changed inside the file

A `git commit --no-verify`, `-n`, or `--no-gpg-sign` requires authentication (`AUTH`). So does
deleting or renaming a file that matches a test-file name pattern (`test_*.py`, `*_test.py`,
`tests/**`, `*.test.js`, `*.spec.ts`, `*.test.jsx`, `*.test.tsx`, `*.spec.jsx`, `*.spec.tsx`,
`*.test.mjs`, `*.spec.mjs`), and so does editing `CODEOWNERS`, a lint or type-check config
(`ruff.toml`, `mypy.ini`, `.eslintrc*`, `eslint.config.*`, including a nested copy in a subdirectory
or monorepo package), or a CI pipeline config.

All three checks are raise-only, and none can tell a legitimate edit from an attempt to hide a
broken test or a disabled lint rule. So a routine `ruff.toml` tweak, or a test rename during an
honest refactor, steps up exactly the same as an attempt to cover something up. That's a deliberate
false-positive cost, not a bug.

The `-n` flag is only recognized following git's own argument grammar, not as a bare substring
match: it can combine with other short commit flags (like `-an`), and it can be swallowed as part of
another option's value (like `-uno` or `-Skeyid`). So a commit message or flag value that happens to
contain the letter `n` isn't mistaken for the bypass.

The same bypass is also caught at the config level, not just as a commit-line flag: `git -c
core.hooksPath=... commit` (which repoints or empties the hooks directory for that one invocation),
`git -c commit.gpgsign=false commit`, and the `--config-env=core.hooksPath=...`
environment-variable indirection (which can't be resolved just by reading the command text, so its
mere presence is enough to require authentication) all require authentication the same as
`--no-verify`.

A repo-root `conftest.py` isn't classed as a test file: the pattern table matches `test_*.py`,
`*_test.py`, and `tests/**` shapes only, not pytest's own file-discovery rules, so deleting or
renaming a root-level `conftest.py` is invisible to this check.

Rename detection only looks at the tool's name: it looks for "rename" or "move" in the name of a
`file_write` or `file_delete` action, so a mere read from a tool merely named something like
"rename_file" doesn't count. A `git mv` or shell `mv` is a command, not a path-targeted tool action,
so it's invisible to this check, and `DestructiveCommandRule` doesn't special-case it either. A
rename tool with any other name is also invisible.

The same gap applies to an outright shell delete: `rm tests/unit/test_auth.py`, `rm -rf tests/`, and
`git rm tests/unit/test_auth.py` are command lines that only `DestructiveCommandRule` evaluates, and
that rule has no concept of test files at all, so all three pass through with no step-up. The
`test_file_removal` check only ever sees a `file_delete` or rename *tool* action, never a shell command
that happens to target a test file.

Deliberately out of scope: catching a `pytest.mark.skip`, `xfail`, or `it.skip` marker added to a
test that's kept in place, a lowered `--cov-fail-under` coverage threshold, an edit that only
touches a `pyproject.toml` `[tool.ruff]` section, or any correlation across sessions like "this
assertion was edited in the same session as an unrelated change." All four would need the actual
file content, an old-versus-new diff, or session history that this rule never reads. `pyproject.toml`
itself is left unflagged for the same reason: it sees constant, routine dependency-bump traffic.

## Package-install checking only looks at the package name in the install command, and only against two small offline lists

`DependencyAdmissionRule` parses `pip`, `npm`, `cargo`, `gem`, `go`, and similar install commands,
and checks only the package name, nothing else, against two bundled, static JSON files: a
known-malicious list (a match is a hard `BLOCK`) and a popular-package list used only to catch names
one character-edit away from a popular one, a common typosquatting trick (a match steps up to
`AUTH`, never `BLOCK`, since this is a statistical signal, not a certainty).

Both lists are snapshots refreshed with each release, not a live feed, and they're small starter
seeds rather than anywhere near what the file format could hold: the popular-package list has 69
names total (22 from PyPI, 22 from npm, 10 from Cargo, 10 from RubyGems, 5 from Go), and the
known-malicious list has 10 names, all npm. See
`src/doberman/engine/rules/data/README.md` for how these lists work.

Being on the popular list is also what exempts a name from the typosquat check. So a real,
legitimate package that isn't in this small seed list can get flagged once, a one-time `AUTH`
step-up, if it happens to be one edit away from a name that is seeded. That's a false positive a
bigger list would remove.

Not caught here: a typosquat of an obscure package, a brand-new malicious package not yet added to
the bundled list, a name that isn't within one edit of anything on the popular list, or an attack
hidden in a lockfile, manifest, or postinstall script rather than in the install command's own
arguments.

Execute-on-install commands are a known gap in this version: `npx <pkg>`, `npm exec <pkg>`, and
`pipx run <pkg>` fetch and run a package in one step, without ever calling an `install` or `add`
subcommand this rule recognizes, so none of them are checked today. All of this is defense-in-depth
against the cheap, common case, a popular-package typo or a documented known-bad name, not a
guarantee against a compromised software supply chain.

## The preview of how many files a delete would affect is a one-time snapshot, and only the MCP proxy re-checks it before acting

Before showing an `AUTH` challenge for a recognized delete command (`rm`, `del`, `erase`, `rd`,
`rmdir`, `Remove-Item`), Doberman computes a bounded, offline count of how many files and
directories the command's targets would affect, the command's blast radius (how much damage it
would do). That count is capped, limited to a fixed amount of wall-clock time, and flags anything
inside `.git` or outside the repo. It's shown alongside the approval prompt.

That count is only a snapshot, taken once. That's exactly why the MCP proxy path recomputes it again
right before actually forwarding the command, and blocks it (reason code `effect_set_diverged`) if
the count changed in between, a TOCTOU check (time-of-check-to-time-of-use: making sure nothing
changed between when Doberman checked and when it actually acts).

Drift between the two counts is only detectable when both are exact. A preview that hit its cap or
couldn't be computed (past the 1,000-entry limit, a timeout, or a delete target built with a live
shell substitution) compares equal to a recount that's also capped or unknown, by design, since both
non-authoritative results share one placeholder value. So `rm -rf node_modules` past the entry cap,
or any delete built with a dynamic `$(...)`, is never caught by this specific guard.

The host-hook path (Claude Code's or Codex's `PreToolUse` hook) has no equivalent recheck after
approval today, so this particular protection only covers the MCP proxy path. In this first version,
the count is for display and the audit log only; it never changes a verdict by itself.
