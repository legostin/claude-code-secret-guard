# secret-guard: design

Status: implemented in 0.1.0 · 2026-10-07

## Goal

Secrets (API keys, tokens, private keys, passwords) must not reach the model, not even once. The person decides, case by case, what the model may see.

"Remove it from the context later" does not meet that goal: once a request with the secret was sent, the model has seen it. So every check runs **before** the text is stored in the conversation or sent.

## Decisions

| Question | Decision | Why |
|---|---|---|
| Detector | The gitleaks binary (`gitleaks stdin`, JSON report on stdout), with secret-guard's own rules over its default set (rules/*.toml, handed over as GITLEAKS_CONFIG_TOML; see the README's Detection) | The same ~200 rules, entropy checks, decoding and `.gitleaks.toml` / `.gitleaksignore` handling as gitleaks itself; updated by the package manager; ~20–40 ms per scan |
| On a finding | Pause and ask, every time a **new** secret shows up | The person decides; a secret cut once is cut again silently |
| Dialog | The engine's own `$.ui.ask` (AskUserQuestion) | A hook may hold a dispatch for 10 s of its own time, but a `$` call in flight does not count; a button in the pane cannot hold the agent |
| Scanner unavailable | Ask: hide or pass unchecked; where nobody can be asked, withhold | Fail closed without blocking the person |
| Dismissed dialog | Hide | Fail closed |
| What the model reads | English, always; the person's texts are `en` or `ru` (`language` option) | The model needs stable markers; the person reads their language |

## Where text enters the context

| Entry | Hook | Behaviour |
|---|---|---|
| A tool's output | `tool.call`, after `next(e)` | Scan `text`. On a new secret, ask. *Cut*: return the tool's own record with the secrets replaced in every string (`redactRecord`), so the model's tool_result **and** the transcript's `toolUseResult` are clean. *Hide*: `{ deny }`. An error result is cut and returned as `{ deny }`. |
| Every stored row | `session.append` | Safety net: cut what is not passed; a text that cannot be checked is withheld. No dialogs here: appends are serialized, and a dialog's own rows would queue behind the one waiting. |
| The person's prompt | `prompt.submit` | Ask; *don't send* → `{ drop }`, and the text goes back to the input box with `$.prompt.fill`. |
| `@path` | `prompt.mention` | Read with `$.fs.read`, scan, ask; *don't attach* → `{ deny }`. The file's text arrives as an attachment, which `prompt.attachment` cuts. |
| Injected attachments | `prompt.attachment` | Cut; on scanner failure, ask. (`session.append` cannot rewrite attachments rendered per request.) |
| CLAUDE.md and context blocks | `prompt.context` | Cut; on scanner failure, ask. |
| The system prompt | `prompt.compose` | Every section cut (on scanner failure, ask), then a section telling the model what placeholders mean and not to try to recover withheld values. |

## Cutting

- A plain finding is replaced wherever its value occurs: `[SECRET:<rule>#<n>]`. `n` is per secret (by SHA-256 prefix) for the session.
- A decoded finding (`Tags: decoded:*`) has a value that is not in the text: the lines that carry it are replaced: `[SECRET:<rule>#<n>: encoded secret, line withheld]`. A line that holds the decoded value verbatim is cut as plain text (gitleaks reports such artefacts spanning lines).
- Several rules for one string: the specific one (`github-pat`) wins over a generic one (`generic-api-key`), the narrower span over the wider; longer needles first.
- If a cut cannot be made whole (an encoded leak's lines are not in the text, or a value is still present afterwards), the text is withheld whole.

## State

`$.state` (session, survives hot reloads), declared in `types/index.d.ts`:

- `entries`: the journal: masks (`ghp_…[40]`), SHA-256 prefixes, sources, decisions, and where each secret stood: the file and line (from a Read's numbering, a Grep match, a changed-file note, an `@`-file) and the lines around it as the model read them (`excerpt`: a placeholder where it was cut, a mask where the model may read the value); never values.
- `expanded`: the log entries opened in the pane; `revealed`: the secrets whose value is shown, by hash.
- `pending`: what the open dialog asks about (source, file and line, masked lines), set before `$.ui.ask` and cleared after; the pane opens on its own to show it.
- `tab`, `openedHistory`, `historyVersion`: the pane's tab, the history events opened, and a counter bumped when the stored history changes (a `$.store` read does not redraw the pane by itself).

`$.store` (on disk, across sessions) holds `history`: the last 400 journal rows of every session, each with its session id and project, without the hash, and with only the lines near the secret.

The random-word rule (hooks/words.ts) runs on the person's prompts and on the record of a `!` command (the `<bash-input>` row the model reads; the command itself runs as typed), up to 2000 characters, on words of 8 characters or more. It scores how often the kind of character changes along a word (a Capital and its lowercase counted as one run), since Shannon entropy cannot separate short passwords from words. scripts/words_experiment.py measures it.

The values themselves, for *show the value*, are kept in the module's memory alone (200 at most, gone on reload). The pane is no part of the model's context; a revealed value hides again after 30 s, so a screenshot pasted into the chat later does not carry it.
- `known`: the registry, one row per secret met (hash, placeholder number, rule, mask, first and last seen, how often, last source). A secret with a number is cut again without a question until the person forgets it.
- `lastNumber`: the placeholder counter. It only grows, so a number is never given to two values.
- `allowed`: hashes the model may read (passed once, or *not a secret*).
- `scanner`: status for the pane and status line.

Raw values exist only in the module's memory, while a text is checked, plus a 64-entry cache of scans keyed by the text's hash.

## Engine constraint worth knowing

`claude plugin validate` refuses passing `$` into a function imported from another file. Every function that calls the engine lives in `hooks/register.tsx`; the other modules are pure.

## Verification

- `claude plugin test .`: 72 tests. `scripts/check_rules.py`: the extra rules against real gitleaks. Pure helpers, plus hooks over the engine's test kit with gitleaks and the dialog stubbed: cut / hide / dismiss / pass / repeat secret / scanner failure / prompt cut / prompt cancel / pane and allowlist / file, line and masked lines in the pane / system prompt / Russian texts.
- Live, against Claude Code 2.1.292 and gitleaks 8.30.1, with `claude -p --plugin-dir`:
  1. `cat` of a file holding a GitHub token: the dialog cannot be shown, the output is hidden; the model answers that it never saw the content; the token occurs **0 times** in the transcript file.
  2. The same with *dismiss → cut* forced, on a file with a plain token and a base64-encoded one: the model quotes `GITHUB_TOKEN=[SECRET:…#1]` and `[SECRET:github-pat#…: encoded secret, line withheld]`; plain, base64 and decoded values occur **0 times** in the transcript.
  3. The first version cut only the stored row: the token stayed in the transcript's `toolUseResult.stdout`. That led to cutting the tool's record in `tool.call`, and check 2 was run again.

## Known limits

Pattern-based detection; no image scanning; a passed value is the model's; the terminal may draw raw output before the rewrite (screen only); no protection when the mod is not loaded; early-access API.
