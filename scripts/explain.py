#!/usr/bin/env python3
"""Shows, line by line, what secret-guard's rules would catch in a file,
never a value: the key, the value's shape (which kinds of characters, how
long) and the rules that caught it.

    python3 scripts/explain.py path/to/config.toml [--all]

Runs gitleaks with secret-guard's rules over the file, as the mod does. It
prints lines that look like an assignment (key = value, key: value), and
lines with a finding; --all prints every line's number.
"""
import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parent.parent
ASSIGNMENT = re.compile(r'''^\s*(?:\d+[:\t→]\s*)?["']?([\w.\-\[\]]+)["']?\s*(=|:=|:)\s*(.*)$''')


def config() -> str:
    bodies = []
    for name in ('keywords.toml', 'entropy.toml'):
        toml = (root / 'rules' / name).read_text()
        bodies.append(toml[toml.index('[[rules]]'):])
    return '[extend]\nuseDefault = true\n\n' + '\n\n'.join(bodies)


def shape(value: str) -> str:
    value = value.strip().strip('"\'`,;')
    if value == '':
        return 'empty'
    kinds = []
    if re.search(r'[a-zа-яё]', value):
        kinds.append('a')
    if re.search(r'[A-ZА-ЯЁ]', value):
        kinds.append('A')
    if re.search(r'\d', value):
        kinds.append('9')
    if re.search(r'[^\w\s]|_', value):
        kinds.append('!')
    return f"{''.join(kinds)} · {len(value)}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('file')
    parser.add_argument('--all', action='store_true')
    args = parser.parse_args()

    text = pathlib.Path(args.file).read_text(errors='replace')
    run = subprocess.run(
        ['gitleaks', 'stdin', '--report-format', 'json', '--report-path', '-',
         '--no-banner', '--log-level', 'error', '--exit-code', '0'],
        input=text, capture_output=True, text=True,
        env={**os.environ, 'GITLEAKS_CONFIG_TOML': config()},
    )
    if run.returncode != 0:
        sys.exit(f'gitleaks failed: {run.stderr.strip()}')
    caught: dict[int, set] = {}
    for finding in json.loads(run.stdout or '[]'):
        for n in range(finding['StartLine'], finding['EndLine'] + 1):
            caught.setdefault(n, set()).add(finding['RuleID'])

    print(f"{'line':>5}  {'key':28} {'value (kinds · length)':24} caught by")
    for n, line in enumerate(text.split('\n'), 1):
        match = ASSIGNMENT.match(line)
        rules = ', '.join(sorted(caught.get(n, []))) or '-'
        if match is None and n not in caught and not args.all:
            continue
        key = match.group(1)[:28] if match else '(no key)'
        value = shape(match.group(3)) if match else ''
        print(f'{n:>5}  {key:28} {value:24} {rules}')


if __name__ == '__main__':
    main()
