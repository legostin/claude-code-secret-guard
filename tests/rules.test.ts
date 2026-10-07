import { describe, expect, test } from 'claude-code/testing'

import { configWith, ENTROPY_RULE, KEYWORD_RULES } from '../hooks/rules'

// What the rules catch is checked against real gitleaks by
// scripts/check_rules.py (a test here has no process to run it in).
describe('configWith', () => {
  test('extends the default set when the project has no config', () => {
    const config = configWith(undefined, { keywords: true, entropy: true })
    expect(config.startsWith('[extend]\nuseDefault = true\n')).toBe(true)
    expect(config).toContain(KEYWORD_RULES)
    expect(config).toContain(ENTROPY_RULE)
  })

  test("extends the project's config by its path", () => {
    expect(configWith("/p/.gitleaks.toml", { keywords: true, entropy: false })).toContain("[extend]\npath = '/p/.gitleaks.toml'")
  })

  test('holds only the rules chosen', () => {
    const config = configWith(undefined, { keywords: false, entropy: true })
    expect(config).not.toContain('password-after-keyword')
    expect(config).toContain('high-entropy-token')
  })
})
