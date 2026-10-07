// Pure helpers: reading gitleaks' report, masking and cutting secrets out of
// text. Nothing here calls the engine.

/** One finding of a gitleaks report, as the guard needs it. */
export type Leak = {
  rule: string
  secret: string
  startLine: number
  endLine: number
  /**
   * gitleaks found it after decoding (base64, hex, percent): `secret` is the
   * decoded value and is not in the text, so the lines are cut instead.
   */
  isEncoded: boolean
}

/**
 * A leak to cut, the rule its placeholder names (the most specific one gitleaks
 * matched the secret under) and the number the model reads it by.
 */
export type Cut = { leak: Leak; rule: string; number: number }

/** A leak the model may not read yet, with its secret's hash. */
export type Found = { leak: Leak; hash: string }

/**
 * One per secret: the same value found twice is one secret. Where gitleaks
 * matched it under several rules, the specific one (`github-pat`) is kept
 * over a generic one (`generic-api-key`).
 */
export function uniqueByHash<T extends { hash: string; leak?: Leak }>(found: readonly T[]): T[] {
  const seen = new Set<string>()
  const specificFirst = [...found].sort((a, b) => generality(a.leak) - generality(b.leak))

  return specificFirst.filter(one => !seen.has(one.hash) && seen.add(one.hash) !== undefined)
}

function generality(leak: Leak | undefined): number {
  return leak?.rule.startsWith('generic') ? 1 : 0
}

/** Reads `gitleaks ... --report-format json --report-path -` output. */
export function parseReport(stdout: string): Leak[] {
  const trimmed = stdout.trim()
  if (trimmed === '') return []
  const raw: unknown = JSON.parse(trimmed)
  if (!Array.isArray(raw)) throw new Error('the report is not a list')

  return raw.map(toLeak).filter(leak => leak.secret !== '')
}

function toLeak(item: unknown): Leak {
  const r = (item ?? {}) as Record<string, unknown>
  const secret = typeof r.Secret === 'string' && r.Secret !== '' ? r.Secret : String(r.Match ?? '')
  const tags = Array.isArray(r.Tags) ? r.Tags : []
  const startLine = Number(r.StartLine ?? 0)

  return {
    rule: String(r.RuleID ?? 'unknown'),
    secret,
    startLine,
    endLine: Number(r.EndLine ?? startLine),
    isEncoded: tags.some(tag => typeof tag === 'string' && tag.startsWith('decoded:')),
  }
}

/** What the person sees of a secret: its first four characters at most, and its length. */
export function mask(secret: string): string {
  const head = secret.length >= 16 ? secret.slice(0, 4) : ''

  return `${head}…[${secret.length}]`
}

export function placeholder(rule: string, number: number, isEncoded: boolean): string {
  return isEncoded
    ? `[SECRET:${rule}#${number}: encoded secret, line withheld]`
    : `[SECRET:${rule}#${number}]`
}

/** What replaces a text that cannot be cut whole. */
export const WHOLE = '[SECRET: text withheld whole]'

/** A string to replace wherever it occurs, and what replaces it. */
export type Needle = { needle: string; label: string }

/**
 * What to look for to cut the leaks found in `text`: a secret's value where
 * it stands in the text, and for an encoded one the whole lines that carry
 * it. Where several leaks claim one string, the specific rule over a
 * generic one, the narrower span over a wider. Undefined when an encoded
 * leak's lines are not in the text: then nothing can be cut, only all.
 */
export function needlesFor(text: string, cuts: readonly Cut[]): Needle[] | undefined {
  const lines = text.split('\n').map(line => line.replace(/\r$/, ''))
  const best = new Map<string, { label: string; rank: number }>()
  const add = (needle: string, label: string, rank: number) => {
    const have = best.get(needle)
    if (have === undefined || rank < have.rank) best.set(needle, { label, rank })
  }

  for (const { leak, rule, number } of cuts) {
    const rank = (rule.startsWith('generic') ? 1000 : 0) + (leak.endLine - leak.startLine)
    if (text.includes(leak.secret)) add(leak.secret, placeholder(rule, number, false), rank)
    if (!leak.isEncoded) continue

    const isInside = leak.startLine >= 1 && leak.endLine >= leak.startLine && leak.endLine <= lines.length
    if (!isInside) return undefined
    // A line holding the decoded value as it is was matched as plain text,
    // and is cut by that value above; the others carry it encoded.
    const encoded = lines
      .slice(leak.startLine - 1, leak.endLine)
      .filter(line => !line.includes(leak.secret) && line.trim().length >= 8)
    if (encoded.length === 0 && !text.includes(leak.secret)) return undefined
    for (const line of encoded) add(line, placeholder(rule, number, true), rank)
  }

  return [...best]
    .map(([needle, { label }]) => ({ needle, label }))
    .sort((a, b) => b.needle.length - a.needle.length)
}

/** Replaces every needle in every string of a value, objects and arrays walked. */
export function redactValue<T>(value: T, needles: readonly Needle[]): T {
  if (typeof value === 'string') {
    let out: string = value
    for (const { needle, label } of needles) out = out.split(needle).join(label)

    return out as T
  }
  if (Array.isArray(value)) return value.map(item => redactValue(item, needles)) as T
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(value)) out[key] = redactValue(item, needles)

    return out as T
  }

  return value
}

/**
 * A value with the leaks found in `text` cut out of every string, or
 * undefined when that cannot be done whole: a secret would be left in.
 */
export function redactRecord<T>(record: T, text: string, cuts: readonly Cut[]): T | undefined {
  const needles = needlesFor(text, cuts)
  if (needles === undefined) return undefined
  const out = redactValue(record, needles)
  const secrets = cuts.map(({ leak }) => leak.secret)
  const isClean = everyString(out, one => secrets.every(secret => !one.includes(secret)))

  return isClean ? out : undefined
}

/** Cuts every leak out of `text`; one that cannot be cut cuts the whole text. */
export function redact(text: string, cuts: readonly Cut[]): string {
  return cuts.length === 0 ? text : (redactRecord(text, text, cuts) ?? WHOLE)
}

function everyString(value: unknown, test: (text: string) => boolean): boolean {
  if (typeof value === 'string') return test(value)
  if (Array.isArray(value)) return value.every(item => everyString(item, test))
  if (value !== null && typeof value === 'object') return Object.values(value).every(item => everyString(item, test))

  return true
}

/**
 * One line of an excerpt: `text` as the model read it, `inFile` as the text
 * holds it with the value masked, when the two differ.
 */
export type ExcerptLine = { n: number; text: string; isHit: boolean; inFile?: string }

/** Where a leak stands and the lines around it, never a value. */
export type Excerpt = {
  /** The file the lines come from, when the text says which. */
  file?: string
  /** The line in that file, or else in the text. */
  line: number
  isFileLine: boolean
  /** The lines carry their own numbers (a Read's, a Grep's); else `n` numbers them. */
  isNumbered: boolean
  lines: ExcerptLine[]
}

// `     6\tcode` or `     6→code`: a Read of a file, a changed-file note.
const NUMBERED = /^\s*(\d+)(?:\t|→)/
// `src/app.ts:12:code`: a Grep with line numbers.
const GREP = /^([^\s:]*[/.][^\s:]*):(\d+)[:-]/
const EXCERPT_LINE = 240

/**
 * The lines around `hit` in `text`, each twice over: as the model read it,
 * every leak shown by `labelOf` (its placeholder where it was cut, its mask
 * where the model may read the value), and as the text holds it with every
 * value masked. The pane never shows a value: a line one could still be read
 * from is dropped to `[…]`.
 */
export function excerpt(
  text: string,
  leaks: readonly Leak[],
  hit: Leak,
  labelOf: (leak: Leak, isEncodedLine: boolean) => string,
  where: { file?: string; isFileText?: boolean } = {},
  around = 6,
): Excerpt {
  const lines = text.split('\n').map(line => line.replace(/\r$/, ''))
  const start = Math.min(Math.max(1, hit.startLine), lines.length)
  const end = Math.min(Math.max(start, hit.endLine), lines.length)
  const from = Math.max(1, start - around)
  const to = Math.min(lines.length, end + around)

  const asRead: Needle[] = []
  const asHeld: Needle[] = []
  const pieces: string[] = []
  for (const leak of leaks) {
    const parts = [leak.secret, ...leak.secret.split('\n').filter(part => part.trim().length >= 8)]
    for (const part of parts) {
      asRead.push({ needle: part, label: labelOf(leak, false) })
      asHeld.push({ needle: part, label: mask(leak.secret) })
      pieces.push(part)
    }
    if (!leak.isEncoded) continue
    for (const line of lines.slice(leak.startLine - 1, leak.endLine)) {
      if (line.includes(leak.secret) || line.trim().length < 8) continue
      asRead.push({ needle: line, label: labelOf(leak, true) })
      asHeld.push({ needle: line, label: '[encoded secret]' })
    }
  }
  const longestFirst = (a: Needle, b: Needle) => b.needle.length - a.needle.length
  asRead.sort(longestFirst)
  asHeld.sort(longestFirst)
  const safe = (line: string) => {
    const clipped = line.length > EXCERPT_LINE ? `${line.slice(0, EXCERPT_LINE - 1)}…` : line

    return pieces.every(piece => !clipped.includes(piece)) ? clipped : '[…]'
  }

  const shown = lines.slice(from - 1, to).map((line, index) => {
    const n = from + index
    const read = safe(redactValue(line, asRead))
    const held = safe(redactValue(line, asHeld))
    const isHit = n >= start && n <= end

    return held === read ? { n, text: read, isHit } : { n, text: read, isHit, inFile: held }
  })

  const first = lines[start - 1] ?? ''
  const numbered = NUMBERED.exec(first)
  if (numbered?.[1] !== undefined) {
    return { file: where.file, line: Number(numbered[1]), isFileLine: true, isNumbered: true, lines: shown }
  }
  const grep = GREP.exec(first)
  if (grep?.[1] !== undefined && grep[2] !== undefined) {
    return { file: grep[1], line: Number(grep[2]), isFileLine: true, isNumbered: true, lines: shown }
  }

  return { file: where.file, line: start, isFileLine: where.isFileText === true, isNumbered: false, lines: shown }
}

/** A content block of a stored row, as `session.append` hands it. */
export type Block = { type: string; [field: string]: unknown }

/**
 * Runs `scrub` over every text the model reads in a row's blocks: text blocks
 * and a tool_result's content, a string or text blocks. Undefined when
 * nothing changed, so the row is passed on as it came.
 */
export async function mapTexts(
  blocks: readonly Block[],
  scrub: (text: string) => Promise<string>,
): Promise<Block[] | undefined> {
  let isChanged = false
  const scrubOne = async (text: string) => {
    const out = await scrub(text)
    isChanged ||= out !== text

    return out
  }

  const out: Block[] = []
  for (const block of blocks) {
    if (block.type === 'text' && typeof block.text === 'string') {
      out.push({ ...block, text: await scrubOne(block.text) })
    } else if (block.type === 'tool_result' && typeof block.content === 'string') {
      out.push({ ...block, content: await scrubOne(block.content) })
    } else if (block.type === 'tool_result' && Array.isArray(block.content)) {
      const inner: unknown[] = []
      for (const item of block.content as unknown[]) {
        const part = (item ?? {}) as Block
        inner.push(part.type === 'text' && typeof part.text === 'string' ? { ...part, text: await scrubOne(part.text) } : item)
      }
      out.push({ ...block, content: inner })
    } else {
      out.push(block)
    }
  }

  return isChanged ? out : undefined
}

/** A SHA-256 prefix: how the guard tells secrets apart without keeping them. */
export async function hashOf(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))

  return [...new Uint8Array(digest)]
    .slice(0, 12)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('')
}
