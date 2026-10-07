// Random-looking words in the person's own prompt: a password typed or pasted
// with nothing around it to say so ("84D83c3po!!!", "3sp7qaA").
//
// Shannon entropy cannot tell a short password from a word: a string of n
// characters has at most log2(n) bits per character, so "planets" scores as
// high as "3sp7qaA". What does tell them apart is how often the kind of
// character changes (lower, upper, digit, symbol) along the word, counting a
// Capital followed by lowercase as one run, as identifiers write words.
//
// Measured (scripts/words_experiment.py, on random passwords and on 593 past
// prompts up to 2000 characters): 73% of passwords of 8 characters or more
// caught, a dialog on 0.2%
// of prompts. Longer prompts are pastes (logs, configs, CSS), where the same
// measure raised a dialog on one in six: gitleaks' rules cover those, as they
// cover tool outputs, where this measure is far too noisy to run at all.

import type { Leak } from './redact'

export const RULE = 'random-word'
/** The longest prompt the measure runs on. */
export const MAX_PROMPT = 2000
const THRESHOLD = 0.3
// Shorter than this a password guards little anyway, and words that short
// read as random far more often.
export const MIN_LENGTH = 8

const TOKEN = /[^\s"'`()[\]{}<>,;|]+/g
// Quotes, markdown marks and the commas and colons of prose are no part of a
// word. A full stop at its end is left out when judging it (a sentence's end),
// and kept out of what is cut.
const EDGE = /^[«»"'’“”‘,;:*#>]+|[«»"'’“”‘,;:*#>]+$/g
const TRAIL = /[.]+$/
// Every mark that is neither a letter nor a digit joins parts: an identifier
// (ACME_DB_PASS), a pattern (^NAME=), a path. A password keeps letters and
// digits mixed inside one part (73Kd91a4qx), which is what is judged.
const SEPARATORS = /[^\p{L}\p{Nd}]+/u
const PURE = /^(?:\p{L}+|\p{Nd}+)$/u
// In a word of several parts ("python3-venv", "ab12.com") a part of letters
// then digits, or digits then letters, is a name too.
const NAME = /^(?:\p{L}+\p{Nd}+|\p{Nd}+\p{L}+)$/u
const DATE = /^\d{4}-\d{2}-\d{2}/
const SKIP = /:\/\/|SECRET:|…/

type Kind = 'lower' | 'upper' | 'digit' | 'symbol'

function kindOf(ch: string): Kind {
  if (/\p{Ll}/u.test(ch)) return 'lower'
  if (/\p{Lu}/u.test(ch)) return 'upper'
  if (/\p{Nd}/u.test(ch)) return 'digit'

  return 'symbol'
}

/**
 * How random a word reads, 0 to 1: kind changes per character. 0 for a word
 * with no letters, letters and nothing but letters, or fewer than three runs.
 */
export function switches(word: string): number {
  const chars = [...word]
  const runs: { kind: Kind | 'word'; size: number }[] = []
  for (const ch of chars) {
    const kind = kindOf(ch)
    const last = runs.at(-1)
    if (last?.kind === kind) last.size += 1
    else runs.push({ kind, size: 1 })
  }
  const letters = runs.filter(run => run.kind === 'lower' || run.kind === 'upper').length
  const hasDigit = runs.some(run => run.kind === 'digit')
  const hasSymbol = runs.some(run => run.kind === 'symbol')
  if (letters === 0 || (!hasDigit && !hasSymbol)) return 0

  // "Encoder": a single capital and the lowercase after it are one word.
  const merged: (Kind | 'word')[] = []
  runs.forEach((run, index) => {
    const before = runs[index - 1]
    if (run.kind === 'lower' && before?.kind === 'upper' && before.size === 1 && merged.at(-1) === 'upper') {
      merged[merged.length - 1] = 'word'
    } else {
      merged.push(run.kind)
    }
  })

  // Two runs ("sha256", "base64") is how identifiers are named; passwords switch more.
  return merged.length < 3 ? 0 : merged.length / chars.length
}

/** A word as it is cut: quotes and marks around it, and a full stop after it, left off. */
export function bare(raw: string): string {
  return raw.replace(EDGE, '').replace(TRAIL, '')
}

/**
 * A word that reads as random: not a flag, date, URL, placeholder, mask,
 * identifier of plain parts, or code of digits with a letter or two.
 */
export function isRandomWord(raw: string): boolean {
  const word = bare(raw)
  const chars = [...word]
  if (chars.length < MIN_LENGTH || chars.length > 64 || word.startsWith('-') || DATE.test(word) || SKIP.test(word)) return false
  const parts = word.split(SEPARATORS).filter(part => part !== '')
  const impure = parts.filter(part => !PURE.test(part) && !(parts.length > 1 && NAME.test(part)))
  if (impure.length === 0 || Math.max(...impure.map(part => [...part].length)) < 4) return false
  const digits = chars.filter(ch => /\p{Nd}/u.test(ch)).length
  const letters = chars.filter(ch => /\p{L}/u.test(ch)).length
  if (digits >= 0.6 * chars.length && letters <= 2) return false

  return switches(word) >= THRESHOLD
}

/** The random-looking words of a text, as leaks the guard handles like gitleaks' own. */
export function randomWords(text: string): Leak[] {
  if (text.length > MAX_PROMPT) return []
  const leaks: Leak[] = []
  text.split('\n').forEach((line, index) => {
    for (const match of line.matchAll(TOKEN)) {
      if (isRandomWord(match[0])) {
        leaks.push({ rule: RULE, secret: bare(match[0]), startLine: index + 1, endLine: index + 1, isEncoded: false })
      }
    }
  })

  return leaks
}
