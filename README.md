# secret-guard: keep secrets out of Claude Code's context

[![CI](https://github.com/legostin/claude-code-secret-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/legostin/claude-code-secret-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**secret-guard** is a [Claude Code](https://claude.com/claude-code) mod (a plugin of function hooks) that stops API keys, tokens, passwords and private keys from reaching the model. Every tool output, prompt and attachment is scanned with [gitleaks](https://github.com/gitleaks/gitleaks) *before* the model reads it. When a secret turns up, the agent pauses and you decide: cut the secret out, hide the whole output, or let it through.

[Русская версия](README.ru.md) · [Website](https://legostin.github.io/claude-code-secret-guard/)

```
Bash: cat .env: secrets found (github-pat ghp_…[40]). What should the model see?
  1. Cut the secrets
  2. Hide the whole output
  3. Let the model see it
  4. Not a secret, allow
```

The model then reads `GITHUB_TOKEN=[SECRET:github-pat#1]` instead of the token, and never learns the value.

## Why

A coding agent reads whatever is in front of it: `cat .env`, a config file, a `curl -v` with an `Authorization` header, a stack trace, a log. Everything it reads is sent to the model and kept in the session transcript. A secret that gets in once is in the conversation for good.

secret-guard puts a checkpoint between your machine and the model:

- **Before the model reads anything.** It hooks the points where text enters the context, not the transcript afterwards. Once a secret has been sent, removing it later does not take it back.
- **The value never reaches the model.** Dialogs and the journal show a mask (`ghp_…[40]`) and a hash. The pane shows the value itself only when you press *show the value*, and hides it again after 30 seconds. The value is kept in the mod's memory alone: not in the session state, not on disk, never in a dialog.
- **When in doubt, it hides.** A dismissed dialog, a scanner failure or a crashed hook withholds the text. Nothing passes silently.

## What it checks

| Where text enters the context | Hook | On a finding |
|---|---|---|
| Output of any tool: Bash, Read, Grep, WebFetch, MCP tools, subagents | `tool.call` | Dialog: cut / hide whole output / pass / not a secret |
| Your own prompt (a pasted key) | `prompt.submit` | Dialog: cut / send as is / don't send (the text goes back to the input box) |
| A file mentioned with `@path` | `prompt.mention` | Dialog: cut / don't attach / attach as is |
| CLAUDE.md, reminders, injected attachments (a changed-file note, a queued prompt…) | `prompt.context`, `prompt.attachment` | Cut automatically and journaled |
| The system prompt's sections | `prompt.compose` | Cut automatically and journaled |
| Every other row stored in the conversation | `session.append` | Safety net: cut automatically |

gitleaks also decodes base64, hex and percent-encoding (up to 5 levels), so `cat .env | base64` is caught too. A line that carries an encoded secret is withheld as a whole.

### Detection

gitleaks' default rules (about 200 known token shapes: `ghp_…`, `sk_live_…`, AWS keys, private keys…) are built for repositories. A conversation leaks differently, so secret-guard adds two layers of its own, each with an option:

| Layer | Catches | Option |
|---|---|---|
| **Keyword rules** | a value after *пароль / password / pwd / passphrase / секрет / secret / токен / token / ключ доступа / access key*, in English or Russian, with up to three words before a separator (`пароль от прод базы: …`, `the password is …`); a password in a URL (`postgres://user:…@host`); a `login:password` pair after *доступ / логин / креды / access / login / credentials* (`доступ к базе admin:…`); a `Bearer` token or `Authorization: Basic`; a password on a command line (`mysql -p…`, `sshpass -p …`, `curl -u user:…`, `--password …`, `PGPASSWORD=…`); `sk-proj-` keys | `keywordRules` |
| **Entropy rule** | a long random-looking token with no known shape, by its Shannon entropy (20–128 characters, upper and lower case and digits, ≥ 4.0 bits per character): about **93%** of random 20–64-character tokens | `entropyRule` |
| **Random words in your prompt** | a password typed with nothing around it (`прод доступ 73Kd91a4qx!!!`): a word of 8+ characters whose kind of character (lower, upper, digit, symbol) keeps changing. About **73%** of such passwords; a dialog on **0.2%** of ordinary prompts (measured on 594 real prompts). Every mark that is neither a letter nor a digit splits a word into parts, so names (`ACME_DB_PASS`, `^API_KEY=`, `process.env.TOKEN`) are never cut: only values are. Prompts up to 2000 characters, and the record of a command you run with `!` (the command itself runs as typed; the model reads it with values cut) | `wordRule` |

secret-guard never scans its own marks: placeholders and masks reach gitleaks as spaces of the same length, and its own dialogs are not checked. Only the value after a keyword is cut, never the word itself. There must be a space or a separator between them, so `secret-guard/…` or `tokens/cache.json` is a path, not a secret. Words (also in markdown emphasis, `**Jira**`), names made of plain parts (a branch `bugfix/SHOP-4242-checkout-page`, a ticket, a tag `node-22-alpine-rc1`), numbers, code (`getenv(…)`), templates (`${X}`), markup, hashes, UUIDs, SRI values, paths, a value that holds a keyword itself (`password: password123`, a list of keyword names) and secret-guard's own placeholders are not treated as secrets. Both layers extend your project's `.gitleaks.toml` when it has one. A `GITLEAKS_CONFIG` you set yourself takes precedence, and then the extra layers are left out.

[`scripts/check_rules.py`](scripts/check_rules.py) checks the rules against real gitleaks in CI: 26 phrases that must be caught, 64 that must not (taken from real Claude Code sessions, lockfiles and git logs), and the entropy rule's recall.

A secret you have already cut once is cut again silently. You are asked again only when a *new* secret shows up.

## Install

You need:

- **Claude Code** with mods (function hooks). Tested on Claude Code 2.1.292.
- **gitleaks** 8.19 or newer:
  ```sh
  brew install gitleaks        # macOS / Linux (Homebrew)
  # or: https://github.com/gitleaks/gitleaks#installing
  ```

Then, at the Claude Code prompt:

```
/plugin install secret-guard --marketplace legostin/claude-code-secret-guard
```

Answer `y` to add the marketplace, then pick a scope (user scope protects every project). The hooks are active right away.

## Use

- **While a dialog is open**, the pane opens on its own and shows, at its top, what the question is about: the source, `file:line`, the lines around with the value masked, and *show the value*. It goes once you answer.
- **`/secrets`** opens the side pane. It has two tabs.

  **This session** is the registry: every value met, listed once, with its status (*cut without a question* or *the model sees it*), how often it was seen and where last. For each value:
  - *show the value*: the value itself, in the pane only, for 30 seconds;
  - *allow from now on* or *cut again*;
  - *forget*: the next time the value appears, you are asked again.

  *Forget all* empties the registry. Placeholder numbers are never reused, so `#3` never means two different values.

  **Log** lists what happened, newest first. For each event:
  - the rule and the mask, and what happened in plain words;
  - where it stood, as `file:line` when the text says (a Read, a Grep match, a changed-file note, an `@`-file), otherwise the line in the text;
  - the lines around it (three each side; six once opened). The line with the secret appears both as the model read it (`GITHUB_TOKEN=[SECRET:github-pat#1]`) and as it is in the file, value masked (`GITHUB_TOKEN=ghp_…[40]`).

  Press an event to open it: the whole source command and the whole file path. *Clear the log* only empties this list. Known secrets stay known.

  **All history** shows the events of every session on this machine, grouped by session (date, project, session id), newest first, up to 400 events. It is kept in the plugin's store on disk: masks and the lines around, never a value or a hash (a short secret's hash could be brute-forced). Delete one session, or clear all of it.

  The pane is drawn for you alone and is never part of the model's context. **Don't paste a screenshot of it into the chat**: images reach the model, and secret-guard does not scan images.

- The **status line** shows `secret-guard: N hidden · /secrets` once something has been withheld. If gitleaks is missing, it shows the install command.
- **Language.** The dialogs and the pane speak English or Russian. Run `/plugin configure secret-guard@secret-guard`, or set it in `settings.json`:
  ```json
  { "pluginConfigs": { "secret-guard@secret-guard": { "options": { "language": "ru" } } } }
  ```
  What the model reads is always English.
- **Project rules.** gitleaks picks up `.gitleaks.toml`, `.gitleaksignore` and `gitleaks:allow` comments from the session's project root.

### What the model sees

- `[SECRET:github-pat#1]` in place of a secret. The number stays the same for the same value throughout the session.
- `[SECRET:github-pat#2: encoded secret, line withheld]` in place of a line that carries an encoded secret.
- A refusal (`the user withheld this Bash output from you…`) when you hide a whole output.
- A short system-prompt section asking it not to try to recover withheld values. It is told to use secrets indirectly (environment variables, files a command reads) or ask you.

## Guarantees and limits

What is verified (see [`tests/`](tests) and the live checks in [`docs/design.md`](docs/design.md)):

- A cut or hidden secret appears neither in the request sent to the model nor in the session transcript file. Both the tool result the model reads and the record the transcript keeps for the screen are rewritten.
- A dismissed dialog hides the output. In a headless run (`claude -p`) no dialog can be shown, so every finding is hidden.
- If gitleaks is missing or fails, you are asked. Where nobody can be asked, the text is withheld.

What it does not do:

- **Short passwords are left alone by design.** A word under 8 characters is not judged by its shape: such a password guards little anyway, and words that short read as random far too often. After a keyword (`пароль: …`) a value is caught from 6 characters.
- **Shannon entropy can't tell a short password from a word.** A string of n characters has at most log₂(n) bits per character, so `planets` scores as high as a password. The random-word rule measures how often the kind of character changes instead. [`scripts/words_experiment.py`](scripts/words_experiment.py) reproduces the numbers on your own prompts and prints only word shapes (`aA9`), never a word.
- **A password of letters only reads as a word** (`password: hunterHunter`), and a hex key looks like a commit hash. Both are let through, to keep the false positives down.
- **The entropy rule is noisy on minified code**: about 8–19 false findings in a 0.3–4.5 MB minified bundle. Turn `entropyRule` off if your agent reads those a lot.
- **WebFetch** hands the whole page to a small helper model before secret-guard sees the result. A secret on a fetched page reaches that model. Fetch with `curl` through Bash when that matters: there the output is checked before anything reads it.
- **A secret split across several outputs** can get through.
- **Images and screenshots are not scanned.**
- **"Let the model see it" means exactly that.** Once you pass a value, the model has it.
- The terminal may briefly *draw* a tool's raw output before it is rewritten. That happens on your screen only: the model and the transcript never get that form.
- If the mod is not loaded (disabled, or a broken install), nothing is protected. Check the status line or `/secrets`.
- Mods are an early-access Claude Code API and may change between releases.

## Develop

```sh
git clone https://github.com/legostin/claude-code-secret-guard
cd claude-code-secret-guard
claude plugin validate .       # what the engine will load and refuse
claude plugin test .           # the test suite (gitleaks and dialogs are stubbed)
claude --plugin-dir .          # a session with the mod loaded from this folder
```

How the pieces fit:

- `hooks/register.tsx`: the hooks, the scanner call, dialogs and the pane. Everything that touches the engine's `$` has to live in this one module.
- `hooks/redact.ts`: pure helpers. Parses the gitleaks report, cuts secrets, builds masks and hashes.
- `hooks/texts.ts`: every string, in English and Russian.
- `types/index.d.ts`: the `$.state` contract (journal, allowlist, numbering, scanner status).

The design and its trade-offs are in [`docs/design.md`](docs/design.md).

## License

[MIT](LICENSE) © Legostin Vyacheslav
