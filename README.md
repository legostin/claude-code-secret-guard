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
- **The value never leaves your machine.** Dialogs, the side pane and the journal show a mask (`ghp_…[40]`) and a hash. The raw value lives only in the mod's memory while a text is being checked.
- **When in doubt, it hides.** A dismissed dialog, a scanner failure or a crashed hook withholds the text. Nothing passes silently.

## What it checks

| Where text enters the context | Hook | On a finding |
|---|---|---|
| Output of any tool: Bash, Read, Grep, WebFetch, MCP tools, subagents | `tool.call` | Dialog: cut / hide whole output / pass / not a secret |
| Your own prompt (a pasted key) | `prompt.submit` | Dialog: cut / send as is / don't send (the text goes back to the input box) |
| A file mentioned with `@path` | `prompt.mention` | Dialog: cut / don't attach / attach as is |
| CLAUDE.md, reminders, injected attachments | `prompt.context`, `prompt.attachment` | Cut automatically and journaled |
| Every other row stored in the conversation | `session.append` | Safety net: cut automatically |

gitleaks also decodes base64, hex and percent-encoding (up to 5 levels), so `cat .env | base64` is caught too. A line that carries an encoded secret is withheld as a whole.

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

- **`/secrets`** opens the side pane. It shows the scanner status, every finding with its mask, source and your decision, and the allowlist. Mark false positives as *not a secret*, or remove entries from the allowlist.
- The **status line** shows `secret-guard: N hidden · /secrets` once something has been withheld. If gitleaks is missing, it shows the install command.
- **Language.** The dialogs and the pane speak English or Russian. Set `language` to `ru` in `/config`, or in `settings.json`:
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

- **It is a pattern scanner.** It finds what gitleaks' rules and entropy checks find (around 200 rule types). A password with no recognizable shape, or a secret split across several outputs, can get through.
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
