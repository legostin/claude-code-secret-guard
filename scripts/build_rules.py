#!/usr/bin/env python3
"""Builds hooks/rules.ts from rules/*.toml: the extra gitleaks rules as TS strings."""
import json
import pathlib

root = pathlib.Path(__file__).resolve().parent.parent


def as_ts(name: str, path: str, doc: str) -> str:
    toml = (root / path).read_text()
    body = toml[toml.index('[[rules]]'):].rstrip()
    lines = ',\n'.join('  ' + json.dumps(line, ensure_ascii=False) for line in body.split('\n'))
    return f'/** {doc} */\nexport const {name} = [\n{lines},\n].join(\'\\n\')\n'


out = (
    '// Built by scripts/build_rules.py from rules/*.toml; edit those, then run it.\n'
    '// scripts/check_rules.py checks the rules against real gitleaks.\n\n'
    + as_ts('KEYWORD_RULES', 'rules/keywords.toml',
            'Secrets after a keyword (EN/RU), in a URL, after Bearer, and sk-proj- keys.')
    + '\n'
    + as_ts('ENTROPY_RULE', 'rules/entropy.toml',
            'A long random-looking token with no known shape, by its Shannon entropy.')
    + '''
export type RuleSet = { keywords: boolean; entropy: boolean }

/**
 * The gitleaks configuration the guard runs with: the chosen rules over the
 * project's own `.gitleaks.toml` (which may itself extend the default set),
 * over gitleaks' default set otherwise.
 */
export function configWith(base: string | undefined, rules: RuleSet): string {
  const extend = base === undefined ? 'useDefault = true' : `path = '${base.replace(/'/g, '')}'`
  const chosen = [rules.keywords ? KEYWORD_RULES : '', rules.entropy ? ENTROPY_RULE : ''].filter(Boolean)

  return `[extend]\\n${extend}\\n\\n${chosen.join('\\n\\n')}\\n`
}
'''
)
(root / 'hooks/rules.ts').write_text(out)
print('wrote hooks/rules.ts')
