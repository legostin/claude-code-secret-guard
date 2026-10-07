#!/usr/bin/env python3
"""Measures hooks/words.ts' measure: how many random passwords it catches, and
how often it would raise a dialog on ordinary prompts.

    python3 scripts/words_experiment.py [--prompts ~/.claude/projects] [--markdown DIR]

Passwords are generated here. Prompts are read from Claude Code transcripts
(the person's own text rows); only counts and word shapes ("aA9") are
printed, never a word, since a past prompt may hold a real secret.
"""
from __future__ import annotations
import argparse
import collections
import glob
import json
import os
import re
import secrets
import string

THRESHOLD = 0.3
MIN_LENGTH = 8
TOKEN = re.compile(r"[^\s\"'`()\[\]{}<>,;|]+")
EDGE = '«»"\'’“”‘,;:*#>'
TRAIL = re.compile(r'[.]+$')
SEPARATORS = re.compile(r"[-–—_.:@/?’'=\\+%×]+")
PURE = re.compile(r'^(?:[^\W\d_]+|\d+)$')
# In a word of several parts ("python3-venv", "ab12.com") a part of letters then
# digits, or digits then letters, is a name too.
NAME = re.compile(r'^(?:[^\W\d_]+\d+|\d+[^\W\d_]+)$')
DATE = re.compile(r'^\d{4}-\d{2}-\d{2}')
SKIP = re.compile(r'://|SECRET:|…')


def kind(ch: str) -> str:
    if ch.islower():
        return 'l'
    if ch.isupper():
        return 'u'
    if ch.isdigit():
        return 'd'
    return 's'


def switches(word: str) -> float:
    runs: list[list] = []
    for ch in word:
        k = kind(ch)
        if runs and runs[-1][0] == k:
            runs[-1][1] += 1
        else:
            runs.append([k, 1])
    kinds = {k for k, _ in runs}
    if not kinds & {'l', 'u'} or not kinds & {'d', 's'}:
        return 0
    merged: list[str] = []
    for index, (k, _) in enumerate(runs):
        before = runs[index - 1] if index else None
        if k == 'l' and before and before[0] == 'u' and before[1] == 1 and merged and merged[-1] == 'u':
            merged[-1] = 'w'
        else:
            merged.append(k)
    return 0 if len(merged) < 3 else len(merged) / len(word)


def is_random(raw: str) -> bool:
    word = TRAIL.sub('', raw.strip(EDGE))
    if not MIN_LENGTH <= len(word) <= 64 or word.startswith('-') or DATE.match(word) or SKIP.search(word):
        return False
    parts = [p for p in SEPARATORS.split(word) if p]
    impure = [p for p in parts if not PURE.match(p) and not (len(parts) > 1 and NAME.match(p))]
    if not impure or max(len(p) for p in impure) < 4:
        return False
    digits = sum(c.isdigit() for c in word)
    letters = sum(c.isalpha() for c in word)
    if digits >= 0.6 * len(word) and letters <= 2:
        return False
    return switches(word) >= THRESHOLD


ABC = string.ascii_letters + string.digits


def password(pick: "int | None" = None) -> str:
    """A password as people make them: random, random with symbols, Word1234!, urlsafe."""
    pick = secrets.randbelow(4) if pick is None else pick
    if pick == 0:
        return ''.join(secrets.choice(ABC) for _ in range(secrets.choice([7, 8, 9, 10, 12])))
    if pick == 1:
        base = ''.join(secrets.choice(ABC) for _ in range(secrets.choice([8, 10])))
        return base + secrets.choice('!@#$%') * secrets.choice([1, 2, 3])
    if pick == 2:
        word = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(5)).capitalize()
        return f'{word}{secrets.randbelow(9000) + 1000}{secrets.choice("!#$")}'
    return secrets.token_urlsafe(9)


def prompts(root: str, exclude: list[str]) -> list[str]:
    out = []
    for path in glob.glob(os.path.join(os.path.expanduser(root), '*', '*.jsonl')):
        if any(name in path for name in exclude):
            continue
        for line in open(path, errors='ignore'):
            if '"type":"user"' not in line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            content = row.get('message', {}).get('content')
            if row.get('type') == 'user' and not row.get('isMeta') and isinstance(content, str) and not content.startswith('<'):
                out.append(content)
    return out


def shape(word: str) -> str:
    return ''.join('a' if c.islower() else 'A' if c.isupper() else '9' if c.isdigit() else c for c in word)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--prompts', default='~/.claude/projects')
    parser.add_argument('--markdown', default=None, help='a folder of .md files, to see the noise on prose with code')
    parser.add_argument('--exclude', action='append', default=[], help='a session id to leave out (one where secrets were typed on purpose)')
    parser.add_argument('--max-length', type=int, default=2000, help='the longest prompt the measure runs on, as in hooks/words.ts')
    args = parser.parse_args()

    sample = [password() for _ in range(3000)]
    print(f'random passwords caught: {sum(map(is_random, sample)) / len(sample):.1%}')
    for pick, name in enumerate(['random 7-12', 'random + symbols', 'Word1234!', 'urlsafe 12']):
        some = [password(pick) for _ in range(1000)]
        print(f'  {name:18} {sum(map(is_random, some)) / len(some):.1%}')

    every = prompts(args.prompts, args.exclude)
    for cap in (300, 600, 1000, 2000, 4000, 10**9):
        some = [t for t in every if len(t) <= cap]
        raised = sum(1 for t in some if any(is_random(w) for w in TOKEN.findall(t)))
        print(f'  prompts up to {cap if cap < 10**9 else "any":>4} chars: {len(some):3} prompts, a dialog on {raised} ({raised / max(1, len(some)):.1%})')
    texts = [t for t in every if len(t) <= args.max_length]
    flagged = [w for t in texts for w in TOKEN.findall(t) if is_random(w)]
    raised = sum(1 for t in texts if any(is_random(w) for w in TOKEN.findall(t)))
    print(f'prompts that would raise a dialog: {raised} of {len(texts)} ({raised / max(1, len(texts)):.1%})')
    print('their word shapes:', collections.Counter(shape(TRAIL.sub("", w.strip(EDGE))) for w in flagged).most_common(10))

    if args.markdown:
        files = [f for f in glob.glob(os.path.join(args.markdown, '**', '*.md'), recursive=True) if 'node_modules' not in f]
        hits = sum(1 for f in files for w in TOKEN.findall(open(f, errors='ignore').read()) if is_random(w))
        print(f'markdown: {hits} hits in {len(files)} files')


if __name__ == '__main__':
    main()
