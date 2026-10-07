import { describe, expect, test } from 'claude-code/testing'

import { isRandomWord, MAX_PROMPT, randomWords, switches } from '../hooks/words'

// Synthetic values in the shapes people type; none is anyone's password.
const typed = ['Qx7mP2kw', '73Kd91a4qx!!!', 'mK9#vL2pQ', 'Zr8fT3wq', 'Hz5$kq2W9', 'Rnkqo4817!', 'xJ3_kq9-Lm2p']

describe('isRandomWord', () => {
  test('catches passwords typed as they are', () => {
    for (const word of typed) expect([word, isRandomWord(word)]).toEqual([word, true])
  })

  test('leaves words, identifiers, dates, URLs, placeholders and masks', () => {
    const leave = [
      'planets',
      'Encoder',
      'utf8Encoder',
      'kebab-case-name',
      'snake_case_name',
      'src/app.ts:12:3',
      'user@host:12:3',
      '2024-01-01T11:42:07.123+00:00',
      '«Слово»',
      'don’t',
      'what?s',
      'https://example.com/a1B2c3',
      'SECRET:password-after-keyword#7',
      'ghp_…[40]',
      'v0.6.1',
      'sha256',
      'x86_64',
      'пароль',
      '1234567',
      'wow!!!',
      'Thanks!',
      'FOO_BAR=1',
      'width:100%',
      'python3-venv',
      'ab12.com',
      '-Dfoo=bar7x',
      '**Status:**',
      'step2.',
      '16K128',
      'aa12–34',
      'Qx7mP2k',
    ]
    for (const word of leave) expect([word, isRandomWord(word)]).toEqual([word, false])
  })
})

describe('switches', () => {
  test('a Capital and its lowercase count as one run', () => {
    expect(switches('Encoder9')).toBe(0)
    expect(switches('9Encoder9')).toBe(3 / 9)
    expect(switches('Qx7mP2kw')).toBe(6 / 8)
  })
})

describe('randomWords', () => {
  test('cuts a trailing ! with the word, leaves the comma and full stop of prose', () => {
    expect(randomWords('вот Qx7mP2kw!!, держи').map(leak => leak.secret)).toEqual(['Qx7mP2kw!!'])
    expect(randomWords('пароль у тебя Qx7mP2kw.').map(leak => leak.secret)).toEqual(['Qx7mP2kw'])
  })

  test('a long prompt (a paste) is left to gitleaks', () => {
    expect(randomWords(`${'лог '.repeat(MAX_PROMPT / 4)} Qx7mP2kw`)).toEqual([])
  })

  test('finds the word and its line', () => {
    expect(randomWords('доступ к базе\nвот он: Qx7mP2kw, спасибо')).toEqual([
      { rule: 'random-word', secret: 'Qx7mP2kw', startLine: 2, endLine: 2, isEncoded: false },
    ])
  })
})
