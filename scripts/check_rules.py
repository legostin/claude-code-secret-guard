#!/usr/bin/env python3
"""Checks rules/*.toml against real gitleaks, as secret-guard runs it.

Every value is random and generated here; nothing real is ever needed. Fails
(exit 1) when a phrase that must be caught is not, when one that must not be
caught is, or when the entropy rule catches less than RECALL_FLOOR of random
tokens.
"""
import json
import os
import pathlib
import secrets
import string
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parent.parent
RECALL_FLOOR = 0.85

ABC = string.ascii_letters + string.digits


def rand(n: int, alphabet: str = ABC) -> str:
    return ''.join(secrets.choice(alphabet) for _ in range(n))


def password(n: int) -> str:
    """A random password with a digit in it: one of letters alone reads as a word, and words are let be."""
    value = rand(n - 1)
    at = secrets.randbelow(n)
    return value[:at] + secrets.choice(string.digits) + value[at:]


def config() -> str:
    bodies = []
    for name in ('keywords.toml', 'entropy.toml'):
        toml = (root / 'rules' / name).read_text()
        bodies.append(toml[toml.index('[[rules]]'):])
    return '[extend]\nuseDefault = true\n\n' + '\n\n'.join(bodies)


def scan(text: str, cfg: str) -> list:
    run = subprocess.run(
        ['gitleaks', 'stdin', '--report-format', 'json', '--report-path', '-',
         '--no-banner', '--log-level', 'error', '--exit-code', '0'],
        input=text, capture_output=True, text=True,
        env={**os.environ, 'GITLEAKS_CONFIG_TOML': cfg},
    )
    if run.returncode != 0:
        sys.exit(f'gitleaks failed: {run.stderr.strip()}')
    return json.loads(run.stdout or '[]')


def main() -> None:
    cfg = config()
    symbols = lambda: password(8) + '!!' + rand(2)

    must_catch = {
        'prod password, Russian keyword': f'прод пароль {symbols()}',
        'пароль: value': f'мой пароль: {password(14)}',
        'words between keyword and dash': f'пароль от базы — {symbols()}',
        'words between keyword and colon': f'пароль от прод базы: {symbols()}',
        'password=value': f'password={password(16)}',
        'the password is value': f'the password is {password(10)}',
        'password for admin: value': f'password for admin: {password(12)}',
        'токен value': f'вот токен {password(24)}',
        'URL credentials': f'postgres://admin:{password(18)}@db.internal:5432/app',
        'Bearer token': 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.' + rand(60) + '.' + rand(43),
        'OpenAI project key': f'OPENAI_API_KEY=sk-proj-{rand(48)}',
        'token with no keyword, 40 chars': f'here you go: {rand(40)}',
        'GitHub token (default rule)': f'ghp_{rand(36)}',
        'доступ к базе user:password': f'доступ к базе {rand(8).lower()}:{password(7)}',
        'логин и пароль: admin:password': f'логин и пароль: admin:{password(10)}',
        'creds for staging: deploy:password': f'creds for staging: deploy:{password(12)}',
        'access to prod db root:password': f'access to prod db root:{password(9)}',
    }
    must_not_catch = {
        'password validation failed for user': 'password validation failed for user',
        'reset your password here': 'click to reset your password here',
        'the password field is required': 'the password field is required',
        'token count exceeds the limit': 'token count exceeds the limit',
        'max_tokens: 4096': 'max_tokens: 4096',
        'token = tokenizer.encode(text)': 'token = tokenizer.encode(text)',
        'password = os.getenv("DB_PASS")': 'password = os.getenv("DB_PASS")',
        'password: ${DB_PASSWORD}': 'password: ${DB_PASSWORD}',
        'a secret-guard placeholder': "token = '[SECRET:github-pat#1]'",
        'a secret-guard mask': 'GITHUB_TOKEN=ghp_…[40]',
        'URL with a variable for a password': 'postgres://user:${PASS}@host/db',
        'URL with no user info': 'see https://github.com/legostin/repo for details',
        'tokens used: 1500000': 'tokens used: 1500000',
        'введите пароль ещё раз': 'введите пароль ещё раз',
        'пароль должен содержать цифры': 'пароль должен содержать цифры и буквы',
        'git commit SHA': 'commit 3f2a9c1e4b7d8a0f6e5c2b1a9d8e7f6a5b4c3d2e',
        'UUID': 'session 9d1bf31e-3fcc-4abb-903d-445799e4edcd',
        'SRI integrity': '"integrity": "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUR"',
        'docker digest': 'image@sha256:4e8e3b6c1d2a5f7b9c0e1d2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
        'a path': 'node_modules/@anthropic-ai/claude-code/cli.js',
        'property access in code': 'gl.COMPRESSED_RGBA_S3TC_DXT1_EXT2',
        'the base64 alphabet': 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
        'session URL': 'Claude-Session: https://claude.ai/code/session_01DDUJwCrmfPJkxor1xMroo8',
        'a token budget tag (Claude Code)': '<total_tokens>15000000 tokens left</total_tokens>',
        'secret:true in an instruction': 'pass secrets as params with secret:true, and dates as YYYY-MM-DD',
        'token counting, in a list': 'streaming, tool use, MCP, agents, caching, token counting, model migration',
        'password: true': 'require password: true',
        'token: null': 'token: null',
        'a path under a secret-guard folder': 'Note: /Users/x/.claude/dev-mods/ab12/secret-guard/.claude-plugin/plugin.json changed on disk.',
        'folders named secrets and tokens': 'see secrets/prod.yaml and tokens/cache.json',
        'secret: a path': 'secret: /etc/ssl/private/server.pem',
        'this rule\'s own source': 'regex = (?i)(?:пароль|парол[яюеи]|password|passwd|pwd|секрет|secret|токен|token|access key)[x]',
        'a keyword given as the value': 'password: password123',
        'keywords listed after a keyword': 'secret: token, password, passphrase',
        'доступ к базе host:port': 'доступ к базе localhost:5432',
        'access log with a timestamp': 'access log at 2024-01-01 11:42:07.123456',
        'login page URL': 'login page at https://example.com/path',
        'account: user:password (placeholder)': 'account: user:password',
        'доступ открыт до 18:00': 'доступ открыт до 18:00',
        'login form at host:port/path': 'login form at localhost:3000/login',
        'access over IPv6': 'access over IPv6 2001:db8::1',
        'access point MAC address': 'access point mac 00:1A:2B:3C:4D:5E',
        'auth: env variable pair': 'auth: ${DB_USER}:${DB_PASS}',
        'the guard\'s own dialog': 'В вашем промпте найдены секреты (random-word …[12]). Что отправить модели?',
        'the guard\'s own placeholder after a keyword': 'пароль [SECRET:random-word#2]',
        'the guard\'s placeholder alone': 'value: [SECRET:random-word#2]{w',
        'SECRET: inside a placeholder': 'SECRET:random-word#2]{w',
        'a mask after a keyword': 'password: ghp_…[40]',
        'an allowlist entry': "regexes = ['^\\$', '(?i)^(password|pass|secret|changeme|xxx+)$']",
    }

    failed = False
    for name, text in must_catch.items():
        rules = sorted({f['RuleID'] for f in scan(text, cfg)})
        ok = bool(rules)
        failed |= not ok
        print(f"{'ok ' if ok else 'MISS'}  catch      {name:40} {', '.join(rules) or '-'}")
    for name, text in must_not_catch.items():
        rules = sorted({f['RuleID'] for f in scan(text, cfg)})
        ok = not rules
        failed |= not ok
        print(f"{'ok ' if ok else 'FP  '}  leave      {name:40} {', '.join(rules) or '-'}")

    sample = [
        f'item {i}: {rand(secrets.choice([20, 24, 32, 40, 48, 64]), ABC if i % 2 else ABC + "-_")}'
        for i in range(1000)
    ]
    caught = len({f['StartLine'] for f in scan('\n'.join(sample), cfg)}) / len(sample)
    ok = caught >= RECALL_FLOOR
    failed |= not ok
    print(f"{'ok ' if ok else 'LOW '}  recall     random tokens, 20-64 chars: {caught:.1%} (floor {RECALL_FLOOR:.0%})")

    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
