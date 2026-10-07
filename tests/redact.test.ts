import { describe, expect, test } from 'claude-code/testing'

import { excerpt, mapTexts, mask, parseReport, placeholder, redact, redactRecord, uniqueByHash, WHOLE } from '../hooks/redact'
import type { Leak } from '../hooks/redact'

const TOKEN = 'ghp_8x2LmQ7vN4pR9sT1wY6zA3bC5dE0fG2hJ4kM'

function leak(over: Partial<Leak> = {}): Leak {
  return { rule: 'github-pat', secret: TOKEN, startLine: 1, endLine: 1, isEncoded: false, ...over }
}

describe('parseReport', () => {
  test('reads gitleaks findings, decoded ones marked', () => {
    const report = JSON.stringify([
      { RuleID: 'github-pat', Secret: TOKEN, Match: TOKEN, StartLine: 1, EndLine: 1, Tags: [] },
      { RuleID: 'github-pat', Secret: TOKEN, StartLine: 3, EndLine: 3, Tags: ['decoded:base64', 'decode-depth:1'] },
    ])
    expect(parseReport(report)).toEqual([leak(), leak({ startLine: 3, endLine: 3, isEncoded: true })])
  })

  test('an empty report is no findings', () => {
    expect(parseReport('[]')).toEqual([])
    expect(parseReport('  \n')).toEqual([])
  })

  test('a report that is not a list throws', () => {
    expect(() => parseReport('{"oops":1}')).toThrow('not a list')
  })
})

describe('mask', () => {
  test('shows four characters and the length of a long secret', () => {
    expect(mask(TOKEN)).toBe('ghp_…[40]')
  })

  test('shows nothing of a short one', () => {
    expect(mask('hunter2hunter')).toBe('…[13]')
  })
})

function cut(over: Partial<Leak> = {}, number = 1) {
  const one = leak(over)

  return { leak: one, rule: one.rule, number }
}

describe('redact', () => {
  test('cuts every occurrence of a plain secret', () => {
    const text = `a=${TOKEN}\nb=${TOKEN}`
    expect(redact(text, [cut()])).toBe('a=[SECRET:github-pat#1]\nb=[SECRET:github-pat#1]')
  })

  test('cuts the lines of an encoded secret', () => {
    const text = 'one\nZXhwb3J0IEdJVEhVQl9UT0tFTj1naHBf\nthree'
    expect(redact(text, [cut({ startLine: 2, endLine: 2, isEncoded: true }, 2)])).toBe(
      'one\n[SECRET:github-pat#2: encoded secret, line withheld]\nthree',
    )
  })

  test('an encoded secret on lines outside the text cuts the whole text', () => {
    expect(redact('one\ntwo', [cut({ startLine: 9, endLine: 9, isEncoded: true })])).toBe(WHOLE)
  })

  test('a longer secret is cut before one it contains', () => {
    const out = redact('k=abcdefghijkl', [
      { leak: leak({ secret: 'abcdefgh' }), rule: 'short', number: 1 },
      { leak: leak({ secret: 'abcdefghijkl' }), rule: 'long', number: 2 },
    ])
    expect(out).toBe('k=[SECRET:long#2]')
  })

  test('gitleaks artefact: a decoded finding whose value stands plain on a line', () => {
    // As gitleaks 8.30 reports a plain token on line 2 and a base64 token on
    // line 3: a generic decoded finding spans both and carries line 2's value.
    const other = 'ghp_Zq7Xv3Lm9Np2Rt5Wy8Bc1Df4Gh6Jk0Ms3Qa7E'
    const blob = 'ZXhwb3J0IEdJVEhVQl9UT0tFTj1naHBfOHgyTG1RN3ZONHBSOXNUMXdZNnpBM2JDNWRFMGZHMmhKNGtN'
    const text = `line one\nGITHUB_TOKEN=${other}\n${blob}\nDEBUG=1`
    const out = redact(text, [
      { leak: leak({ secret: other, startLine: 2, endLine: 2 }), rule: 'github-pat', number: 1 },
      { leak: leak({ rule: 'generic-api-key', secret: other, startLine: 2, endLine: 2 }), rule: 'github-pat', number: 1 },
      { leak: leak({ startLine: 3, endLine: 3, isEncoded: true }), rule: 'github-pat', number: 2 },
      {
        leak: leak({ rule: 'generic-api-key', secret: other, startLine: 2, endLine: 3, isEncoded: true }),
        rule: 'github-pat',
        number: 1,
      },
    ])
    expect(out).toBe(
      'line one\nGITHUB_TOKEN=[SECRET:github-pat#1]\n[SECRET:github-pat#2: encoded secret, line withheld]\nDEBUG=1',
    )
  })
})

describe('mapTexts', () => {
  test('rewrites text blocks and tool results, keeps the rest', async () => {
    const blocks = [
      { type: 'text', text: 'a' },
      { type: 'tool_result', tool_use_id: 't1', content: 'b' },
      { type: 'tool_result', tool_use_id: 't2', content: [{ type: 'text', text: 'c' }, { type: 'image' }] },
      { type: 'tool_use', id: 't3', input: { x: 'a' } },
    ]
    const out = await mapTexts(blocks, async text => text.toUpperCase())
    expect(out).toEqual([
      { type: 'text', text: 'A' },
      { type: 'tool_result', tool_use_id: 't1', content: 'B' },
      { type: 'tool_result', tool_use_id: 't2', content: [{ type: 'text', text: 'C' }, { type: 'image' }] },
      { type: 'tool_use', id: 't3', input: { x: 'a' } },
    ])
  })

  test('answers undefined when nothing changed', async () => {
    expect(await mapTexts([{ type: 'text', text: 'a' }], async text => text)).toBeUndefined()
  })
})

describe('redactRecord', () => {
  test('cuts a secret from every string of a tool record', () => {
    const record = { stdout: `GITHUB_TOKEN=${TOKEN}`, stderr: '', interrupted: false, extra: [TOKEN] }
    expect(redactRecord(record, record.stdout, [cut()])).toEqual({
      stdout: 'GITHUB_TOKEN=[SECRET:github-pat#1]',
      stderr: '',
      interrupted: false,
      extra: ['[SECRET:github-pat#1]'],
    })
  })

  test('cuts an encoded secret by its whole line', () => {
    const text = 'one\nZXhwb3J0IEdJVEhVQl9UT0tFTj1naHBf\nthree'
    expect(redactRecord({ stdout: text }, text, [cut({ startLine: 2, endLine: 2, isEncoded: true })])).toEqual({
      stdout: 'one\n[SECRET:github-pat#1: encoded secret, line withheld]\nthree',
    })
  })

  test('answers undefined when an encoded line is not in the text', () => {
    expect(redactRecord({ stdout: 'one' }, 'one', [cut({ startLine: 7, endLine: 7, isEncoded: true })])).toBeUndefined()
  })
})

describe('uniqueByHash', () => {
  test('keeps the specific rule over a generic one for the same secret', () => {
    const found = [
      { hash: 'h1', leak: leak({ rule: 'generic-api-key' }) },
      { hash: 'h1', leak: leak({ rule: 'github-pat' }) },
    ]
    expect(uniqueByHash(found).map(one => one.leak.rule)).toEqual(['github-pat'])
  })
})

// As the journal labels leaks: the placeholder the model read.
const asRead = (one: Leak, isEncodedLine: boolean) => placeholder(one.rule, 1, isEncodedLine)

describe('excerpt', () => {
  test('a Read output: the file line from its numbering, each line as read and as held', () => {
    const text = ['     4\timport x', '     5\t', `     6\tconst TOKEN = '${TOKEN}'`, '     7\t', '     8\tfunction leak() {'].join('\n')
    const hit = leak({ startLine: 3, endLine: 3 })
    const where = excerpt(text, [hit], hit, asRead, { file: '/p/tests/a.ts' })
    expect(where).toMatchObject({ file: '/p/tests/a.ts', line: 6, isFileLine: true, isNumbered: true })
    expect(where.lines).toEqual([
      { n: 1, text: '     4\timport x', isHit: false },
      { n: 2, text: '     5\t', isHit: false },
      {
        n: 3,
        text: "     6\tconst TOKEN = '[SECRET:github-pat#1]'",
        isHit: true,
        inFile: "     6\tconst TOKEN = 'ghp_…[40]'",
      },
      { n: 4, text: '     7\t', isHit: false },
      { n: 5, text: '     8\tfunction leak() {', isHit: false },
    ])
  })

  test('six lines each side are kept', () => {
    const text = Array.from({ length: 20 }, (_, i) => (i === 9 ? `k=${TOKEN}` : `line ${i + 1}`)).join('\n')
    const hit = leak({ startLine: 10, endLine: 10 })
    const where = excerpt(text, [hit], hit, asRead)
    expect(where.lines.map(line => line.n)).toEqual([4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
    expect(where.isNumbered).toBe(false)
  })

  test('a Grep line: the file and line from the match itself', () => {
    const text = `src/config.ts:12:  token: '${TOKEN}',`
    const where = excerpt(text, [leak()], leak(), asRead)
    expect(where).toMatchObject({ file: 'src/config.ts', line: 12, isFileLine: true, isNumbered: true })
    expect(JSON.stringify(where)).not.toContain(TOKEN)
  })

  test('plain output: the line in the text; masked where the model saw the value', () => {
    const hit = leak({ startLine: 3, endLine: 3 })
    const where = excerpt(`a\nb\nGITHUB_TOKEN=${TOKEN}`, [hit], hit, one => mask(one.secret))
    expect(where).toMatchObject({ line: 3, isFileLine: false })
    expect(where.lines.at(-1)).toEqual({ n: 3, text: 'GITHUB_TOKEN=ghp_…[40]', isHit: true })
  })

  test('no line shows any secret of the text, a part of a multi-line one included', () => {
    const key = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----'
    const text = `before\n${key}\nafter ${TOKEN}`
    const pem = leak({ rule: 'private-key', secret: key, startLine: 2, endLine: 4 })
    const where = excerpt(text, [pem, leak({ startLine: 5, endLine: 5 })], pem, asRead)
    const shown = JSON.stringify(where)
    expect(shown).not.toContain('MIIEvQIBADANBgkqhkiG9w0BAQEFAASC')
    expect(shown).not.toContain(TOKEN)
  })
})
