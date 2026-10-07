// secret-guard: gitleaks looks at everything about to enter the model's
// context; what it finds is cut out, withheld or passed as the person decides.
//
//   tool.call          a tool's output: asks, then hides it or lets it on
//   session.append     every row stored and sent: cuts what is not passed
//   prompt.submit      the person's own prompt: asks before it is sent
//   prompt.mention     an @-mentioned file: asks before it is attached
//   prompt.attachment  files, reminders, hook output the engine injects
//   prompt.context     CLAUDE.md and the first message's context blocks
//   prompt.compose     the system prompt's sections
//
// Secrets live only in this module's memory, for as long as a text is being
// checked. The journal and the allowlist hold masks and hashes.

import { atom, read, update } from 'claude-code'
import type { EngineInterface, EventOf, Register, ToolCallResult } from 'claude-code'

import type { Decision, Entry } from '../types'
import { excerpt, hashOf, mapTexts, mask, parseReport, placeholder, redact, redactRecord, uniqueByHash } from './redact'
import type { Cut, Found, Leak } from './redact'
import {
  clock,
  describeCall,
  hiddenNote,
  keyOf,
  MENTION_FAILED,
  MENTION_SKIPPED,
  NOTE,
  pathIn,
  shortPath,
  textsFor,
  TOOL_FAILED,
  withheld,
} from './texts'

const PANE = 'secret-guard'

const entries = atom({ plugin: 'secret-guard', key: 'entries' } as const, [])
const allowed = atom({ plugin: 'secret-guard', key: 'allowed' } as const, [])
const labels = atom({ plugin: 'secret-guard', key: 'labels' } as const, {})
const scanner = atom({ plugin: 'secret-guard', key: 'scanner' } as const, { status: 'unknown', detail: '' })
const expanded = atom({ plugin: 'secret-guard', key: 'expanded' } as const, [])
const revealed = atom({ plugin: 'secret-guard', key: 'revealed' } as const, [])

const GITLEAKS_ARGS = [
  'stdin',
  '--report-format', 'json',
  '--report-path', '-',
  '--no-banner',
  '--log-level', 'error',
  '--exit-code', '0',
]
const GITLEAKS_PATHS = ['gitleaks', '/opt/homebrew/bin/gitleaks', '/usr/local/bin/gitleaks']
const MIN_LENGTH = 8
const CACHE_SIZE = 64
const MAX_ENTRIES = 200

// Rows no secret reaches: the model's own words, a compaction of rows already
// checked, and notices the model never reads.
const QUIET_DOORS: ReadonlySet<string> = new Set(['response', 'compaction', 'notice'])
const HIDING: ReadonlySet<Decision> = new Set(['redacted', 'recut', 'hidden', 'dropped', 'auto-redacted', 'withheld'])
const ALLOWABLE: ReadonlySet<Decision> = new Set(['redacted', 'recut', 'hidden', 'dropped', 'auto-redacted'])
// The model never read the value under these; it read a placeholder under
// MODEL_READ, the value itself under SAW, and nothing at all under NOTHING.
const CUT: ReadonlySet<Decision> = new Set(['redacted', 'recut', 'hidden', 'dropped', 'auto-redacted', 'withheld'])
const MODEL_READ: ReadonlySet<Decision> = new Set(['redacted', 'recut', 'auto-redacted'])
const SAW: ReadonlySet<Decision> = new Set(['passed', 'allowlisted'])
const NOTHING: ReadonlySet<Decision> = new Set(['hidden', 'dropped', 'withheld'])
// Lines shown around a finding before it is opened; opened, all that were kept.
const AROUND_CLOSED = 3

type ScanResult = { isScanned: true; leaks: Leak[] } | { isScanned: false; reason: string }

/** The text a finding was made in, so the journal can say where it stood. */
type Origin = { text: string; leaks: readonly Leak[]; file?: string; isFileText?: boolean }

// A tool's output is scanned at tool.call and again as its row is appended:
// the second look is answered from here, by the text's hash.
const scans = new Map<string, Leak[]>()
// Texts the person let through unchecked when the scanner failed.
const passedTexts = new Set<string>()
// The values the journal's secrets had, by hash, for the person to see in the
// pane on request. Here alone: never in $.state, the store or a dialog, and
// gone when the module reloads.
const values = new Map<string, string>()
const VALUES_KEPT = 200
const REVEAL_MS = 30_000
let gitleaks: string | undefined
// What the person reads, in the language the `language` option names.
let t = textsFor('en')

export const register: Register = (on, options) => {
  t = textsFor(options.language)

  on('session.start', async ($, e, next) => {
    await $.command.register({ name: 'secrets', description: t.commandDescription })
    await probe($)

    return next(e)
  })

  on('command.run', { command: 'secrets' }, async $ => {
    await $.ui.open({ id: PANE, title: 'secret-guard' })

    return { text: t.paneOpened }
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, ($, e) => drawPane($, e))

  // The system prompt: every section checked (env details, instructions other
  // plugins add), then the guard's own note for the model.
  on('prompt.compose', async ($, e, next) => {
    const composed = await next(e)
    const sections = []
    for (const section of composed.sections) {
      const text = await scrubAsking($, section.text, t.systemPrompt(section.id))
      sections.push(text === section.text ? section : { ...section, text })
    }

    return { ...composed, sections: [...sections, { id: 'secret-guard', text: NOTE, scope: 'session' }] }
  })

  // A tool's output, after the tool ran and before the model reads it. A cut
  // is made in the tool's own record, so neither the model nor the record the
  // transcript keeps for the screen holds the secret; session.append checks
  // the row once more as it is stored.
  on('tool.call', async ($, e, next) => {
    const ran = await next(e)
    if (ran.deny !== undefined || ran.text === undefined || ran.text === '') return ran

    const who = e.agentId === undefined ? '' : t.subagentPrefix
    const source = describeCall(String(e.tool), e as unknown as Record<string, unknown>, who)
    const result = await scanText($, ran.text)
    if (!result.isScanned) {
      if ((await askFailure($, source, result.reason)) === 'pass') {
        passedTexts.add(await hashOf(ran.text))
        await recordFailure($, source, result.reason, 'passed')

        return ran
      }
      await recordFailure($, source, result.reason, 'withheld')

      return { deny: withheld(result.reason) }
    }

    const found = await unresolved($, result.leaks)
    if (found.length === 0) return ran
    const input = e as unknown as Record<string, unknown>
    const origin: Origin = {
      text: ran.text,
      leaks: result.leaks,
      ...(typeof input.file_path === 'string' ? { file: input.file_path } : {}),
    }
    const { known, novel } = await splitKnown($, found)
    if (novel.length === 0) {
      await record($, source, known, 'recut', origin)

      return cutOutput($, ran, known, String(e.tool))
    }

    const choice = await ask($, t.toolQuestion(source, novel), t.toolOptions, 'redact', 'hide')
    if (choice === 'hide') {
      await numbersFor($, found)
      await record($, source, found, 'hidden', origin)

      return { deny: hiddenNote(String(e.tool), found) }
    }
    if (choice === 'pass' || choice === 'allow') {
      const reason = choice === 'pass' ? 'passed' : 'allowlisted'
      await allow($, novel, reason)
      await record($, source, novel, reason, origin)
      await record($, source, known, 'recut', origin)

      return known.length === 0 ? ran : cutOutput($, ran, known, String(e.tool))
    }
    await numbersFor($, found)
    await record($, source, novel, 'redacted', origin)
    await record($, source, known, 'recut', origin)

    return cutOutput($, ran, found, String(e.tool))
  }).catch(($, e, next) =>
    next.error.kind === 're-entry'
      ? next(e)
      : { deny: TOOL_FAILED },
  )

  // Every row the conversation keeps, before it is stored and sent: what is
  // not passed is cut, and a text that cannot be checked is withheld whole.
  on('session.append', async ($, e, next) => {
    if (QUIET_DOORS.has(e.door) || e.message.type === 'system') return next(e)
    const source = `${t.doors[e.door] ?? e.door}${e.agentId === undefined ? '' : t.subagentSuffix}`
    const content = await mapTexts(e.message.content, text => scrubQuietly($, text, source))

    return content === undefined ? next(e) : next({ ...e, message: { ...e.message, content } })
  }).catch(async ($, e, next) => {
    if (next.called) return next(e)
    const content = await mapTexts(e.message.content, async () => withheld('the check failed'))

    return next({ ...e, message: { ...e.message, content: content ?? e.message.content } })
  })

  on('prompt.submit', async ($, e, next) => {
    const result = await scanText($, e.text)
    if (!result.isScanned) {
      if ((await askFailure($, t.prompt, result.reason)) === 'pass') {
        passedTexts.add(await hashOf(e.text))

        return next(e)
      }
      await recordFailure($, t.prompt, result.reason, 'dropped')
      await refill($, e.text)

      return { drop: t.promptDroppedFailure(result.reason) }
    }

    const found = await unresolved($, result.leaks)
    if (found.length === 0) return next(e)
    const origin: Origin = { text: e.text, leaks: result.leaks }
    const { known, novel } = await splitKnown($, found)
    const choice = novel.length === 0 ? 'redact' : await ask($, t.promptQuestion(novel), t.promptOptions, 'redact', 'cancel')
    if (choice === 'cancel') {
      await numbersFor($, found)
      await record($, t.prompt, found, 'dropped', origin)
      await refill($, e.text)

      return { drop: t.promptDropped }
    }
    if (choice === 'send' || choice === 'allow') {
      const reason = choice === 'send' ? 'passed' : 'allowlisted'
      await allow($, novel, reason)
      await record($, t.prompt, novel, reason, origin)
    }
    const cut = choice === 'redact' ? found : known
    const cuts = await cutsFor($, cut)
    if (choice === 'redact') await record($, t.prompt, novel, 'redacted', origin)
    await record($, t.prompt, known, 'recut', origin)

    return next({ ...e, text: redact(e.text, cuts) })
  }).catch(($, e, next) =>
    next.called ? next(e) : { drop: t.promptFailed },
  )

  // An @-mentioned file, before the engine reads it. Its text reaches the
  // model as an attachment, which prompt.attachment cuts.
  on('prompt.mention', async ($, e, next) => {
    let text: string
    try {
      const content = await $.fs.read(e.path)
      if (typeof content !== 'string') return next(e)
      text = content
    } catch {
      return next(e)
    }
    const result = await scanText($, text)
    if (!result.isScanned) return next(e)

    const found = await unresolved($, result.leaks)
    const { novel } = await splitKnown($, found)
    if (novel.length === 0) return next(e)

    const source = `@${e.mention}`
    const origin: Origin = { text, leaks: result.leaks, file: e.path, isFileText: true }
    const choice = await ask($, t.mentionQuestion(source, novel), t.mentionOptions, 'redact', 'skip')
    if (choice === 'skip') {
      await numbersFor($, found)
      await record($, source, found, 'dropped', origin)
      $.ui.toast(t.mentionSkipped(source))

      return { deny: MENTION_SKIPPED }
    }
    if (choice === 'pass' || choice === 'allow') {
      const reason = choice === 'pass' ? 'passed' : 'allowlisted'
      await allow($, novel, reason)
      await record($, source, novel, reason, origin)

      return next(e)
    }
    await numbersFor($, found)
    await record($, source, found, 'redacted', origin)

    return next(e)
  }).catch(($, e, next) =>
    next.called ? next(e) : { deny: MENTION_FAILED },
  )

  on('prompt.attachment', async ($, e, next) => {
    const ran = await next(e)
    if (ran.text === null || ran.text === '') return ran

    const file = pathIn(ran.text)
    const where = file === undefined ? undefined : shortPath(file, await $.session.root())

    return { text: await scrubAsking($, ran.text, t.attachment(e.type, where), file) }
  }).catch(() => ({ text: withheld('the check of this attachment failed') }))

  on('prompt.context', async ($, e, next) => {
    const ran = await next(e)
    let isChanged = false
    const blocks = []
    for (const block of ran.blocks) {
      const text = await scrubAsking($, block.text, t.context(block.name))
      isChanged ||= text !== block.text
      blocks.push(text === block.text ? block : { ...block, text })
    }

    return isChanged ? { ...ran, blocks } : ran
  }).catch(() => ({ blocks: [] }))
}

// --- scanning --------------------------------------------------------------

/** Runs gitleaks over a text, and keeps the status line in step with it. */
async function scanText($: EngineInterface, text: string): Promise<ScanResult> {
  if (text.length < MIN_LENGTH) return { isScanned: true, leaks: [] }
  const key = await hashOf(text)
  const hit = scans.get(key)
  if (hit !== undefined) return { isScanned: true, leaks: hit }

  const cwd = await $.session.root()
  let reason = t.notFound
  for (const bin of gitleaks === undefined ? GITLEAKS_PATHS : [gitleaks]) {
    let ran
    try {
      ran = await $.process.run([bin, ...GITLEAKS_ARGS], { cwd, stdin: text, timeoutMs: 20_000 })
    } catch (error) {
      reason = `${bin}: ${messageOf(error)}`
      continue
    }
    if (ran.exitCode !== 0) {
      return { isScanned: false, reason: t.exited(ran.exitCode, firstLine(ran.stderr)) }
    }
    let leaks: Leak[]
    try {
      leaks = parseReport(ran.stdout)
    } catch (error) {
      return { isScanned: false, reason: t.unreadable(messageOf(error)) }
    }
    scans.set(key, leaks)
    if (scans.size > CACHE_SIZE) scans.delete(scans.keys().next().value ?? '')
    if (gitleaks !== bin) {
      gitleaks = bin
      await update($, scanner, () => ({ status: 'ok', detail: bin }))
      await refreshStatus($)
    }

    return { isScanned: true, leaks }
  }
  gitleaks = undefined

  return { isScanned: false, reason }
}

/** Finds the installed gitleaks and says so in the pane and status line. */
async function probe($: EngineInterface): Promise<void> {
  for (const bin of GITLEAKS_PATHS) {
    try {
      const ran = await $.process.run([bin, 'version'], { timeoutMs: 10_000 })
      if (ran.exitCode === 0) {
        gitleaks = bin
        await update($, scanner, () => ({ status: 'ok', detail: `gitleaks ${ran.stdout.trim()}` }))
        await refreshStatus($)

        return
      }
    } catch {
      // not at this path; try the next
    }
  }
  await update($, scanner, () => ({ status: 'missing', detail: t.missing }))
  await refreshStatus($)
}

// --- what the model may read ----------------------------------------------

/** The leaks the model may not read: those neither passed nor allowlisted. */
async function unresolved($: EngineInterface, leaks: readonly Leak[]): Promise<Found[]> {
  const ok = new Set((await read($, allowed)).map(one => one.hash))
  const found: Found[] = []
  for (const leak of leaks) {
    const hash = await hashOf(leak.secret)
    if (!ok.has(hash)) found.push({ leak, hash })
  }

  return found
}

/** Secrets cut before (cut again without asking) and new ones (asked about). */
async function splitKnown($: EngineInterface, found: readonly Found[]): Promise<{ known: Found[]; novel: Found[] }> {
  const numbers = await read($, labels)

  return {
    known: found.filter(one => numbers[one.hash] !== undefined),
    novel: found.filter(one => numbers[one.hash] === undefined),
  }
}

/** Gives each secret the number the model reads it under, keeping the ones it has. */
async function numbersFor($: EngineInterface, found: readonly Found[]): Promise<Record<string, number>> {
  let numbers: Record<string, number> = {}
  await update($, labels, current => {
    const next = { ...current }
    let count = Object.keys(next).length
    for (const { hash } of found) {
      if (next[hash] === undefined) next[hash] = ++count
    }
    numbers = next

    return next
  })

  return numbers
}

async function cutsFor($: EngineInterface, found: readonly Found[]): Promise<Cut[]> {
  const numbers = await numbersFor($, found)
  const rules = new Map(uniqueByHash(found).map(one => [one.hash, one.leak.rule]))

  return found.map(({ leak, hash }) => ({ leak, rule: rules.get(hash) ?? leak.rule, number: numbers[hash] ?? 0 }))
}

/**
 * A tool's answer with the secrets cut out of its record: the model reads the
 * record mapped by the tool's own mapper, and the transcript keeps it for the
 * screen. An error's text is cut and given as the call's refusal, which the
 * model also reads as an error. Withheld whole when it cannot be cut.
 */
async function cutOutput(
  $: EngineInterface,
  ran: ToolCallResult,
  found: readonly Found[],
  tool: string,
): Promise<ToolCallResult> {
  const cuts = await cutsFor($, found)
  const text = ran.text ?? ''
  if (ran.isError === true) return { deny: redact(text, cuts) }
  const result = redactRecord(ran.result, text, cuts)
  if (result === undefined) return { deny: hiddenNote(tool, found) }

  return ran.context === undefined ? { result } : { result, context: ran.context }
}

/** Lets the model read these secrets from now on. */
async function allow($: EngineInterface, found: readonly Found[], reason: 'passed' | 'allowlisted'): Promise<void> {
  await update($, allowed, list => {
    const have = new Set(list.map(one => one.hash))
    const added = uniqueByHash(found)
      .filter(one => !have.has(one.hash))
      .map(({ leak, hash }) => ({ hash, rule: leak.rule, mask: mask(leak.secret), reason }))

    return [...list, ...added]
  })
}

/**
 * Cuts the secrets out of a text where no dialog can be shown: a new secret
 * is cut and journaled, a known one cut again, and a text the scanner could
 * not check is withheld whole.
 */
async function scrubQuietly($: EngineInterface, text: string, source: string, file?: string): Promise<string> {
  if (passedTexts.has(await hashOf(text))) return text
  const result = await scanText($, text)
  if (!result.isScanned) {
    await recordFailure($, source, result.reason, 'withheld')
    $.ui.toast(t.withheldToast(source))

    return withheld(result.reason)
  }

  return cutFound($, source, await unresolved($, result.leaks), { text, leaks: result.leaks, file })
}

/** As scrubQuietly, but a text the scanner could not check is the person's to pass. */
async function scrubAsking($: EngineInterface, text: string, source: string, file?: string): Promise<string> {
  if (passedTexts.has(await hashOf(text))) return text
  const result = await scanText($, text)
  if (!result.isScanned) {
    if ((await askFailure($, source, result.reason)) === 'pass') {
      passedTexts.add(await hashOf(text))
      await recordFailure($, source, result.reason, 'passed')

      return text
    }
    await recordFailure($, source, result.reason, 'withheld')

    return withheld(result.reason)
  }

  return cutFound($, source, await unresolved($, result.leaks), { text, leaks: result.leaks, file })
}

async function cutFound($: EngineInterface, source: string, found: readonly Found[], origin: Origin): Promise<string> {
  const { text } = origin
  if (found.length === 0) return text
  const { known, novel } = await splitKnown($, found)
  const cuts = await cutsFor($, found)
  await record($, source, known, 'recut', origin)
  if (novel.length > 0) {
    await record($, source, novel, 'auto-redacted', origin)
    $.ui.toast(t.autoCut(novel[0]?.leak.rule ?? 'secret', source))
  }

  return redact(text, cuts)
}

// --- asking -------------------------------------------------------------

/**
 * Pauses until the person picks an option. A dismissed dialog answers
 * `dismissed`; free text typed under "Other" answers `fallback`.
 */
async function ask<O extends Record<string, string>>(
  $: EngineInterface,
  question: string,
  options: O,
  fallback: keyof O & string,
  dismissed: keyof O & string,
): Promise<keyof O & string> {
  try {
    const answer = await $.ui.ask(question, { header: t.header, options: Object.values<string>(options) })

    return keyOf(options, answer, fallback)
  } catch {
    return dismissed
  }
}

function askFailure($: EngineInterface, source: string, reason: string) {
  return ask($, t.failureQuestion(source, reason), t.failureOptions, 'hide', 'hide')
}

async function refill($: EngineInterface, text: string): Promise<void> {
  try {
    await $.prompt.fill({ text, mode: 'replace' })
  } catch {
    // the box is the person's; nothing to undo
  }
}

// --- the journal ----------------------------------------------------------

/**
 * Adds one journal row per secret, with where it stood in `origin`'s text:
 * the file and line when the text says which, and the lines around it with
 * every secret masked.
 */
async function record(
  $: EngineInterface,
  source: string,
  found: readonly Found[],
  decision: Decision,
  origin?: Origin,
): Promise<void> {
  if (found.length === 0) return
  const numbers = await read($, labels)
  const at = await $.clock.now()
  const root = origin === undefined ? '' : await $.session.root()

  // Each leak of the text as the model read it: its placeholder where it was
  // cut, its mask where the model may read it (the pane never shows a value).
  const passed = new Set((await read($, allowed)).map(one => one.hash))
  const hashes = new Map<string, string>()
  for (const leak of origin?.leaks ?? []) hashes.set(leak.secret, await hashOf(leak.secret))
  const withHashes = (origin?.leaks ?? []).map(leak => ({ leak, hash: hashes.get(leak.secret) ?? '' }))
  const rules = new Map(uniqueByHash(withHashes).map(one => [one.hash, one.leak.rule]))
  const labelOf = (leak: Leak, isEncodedLine: boolean) => {
    const hash = hashes.get(leak.secret) ?? ''
    const number = numbers[hash]
    if (number === undefined || passed.has(hash)) return isEncodedLine ? '[encoded secret]' : mask(leak.secret)

    return placeholder(rules.get(hash) ?? leak.rule, number, isEncodedLine)
  }
  const placeOf = (leak: Leak) => {
    if (origin === undefined) return {}
    const where = excerpt(origin.text, origin.leaks, leak, labelOf, { file: origin.file, isFileText: origin.isFileText })

    return {
      ...(where.file === undefined ? {} : { file: shortPath(where.file, root), filePath: where.file }),
      line: where.line,
      isFileLine: where.isFileLine,
      isNumbered: where.isNumbered,
      lines: where.lines,
    }
  }
  for (const { leak, hash } of found) {
    values.delete(hash)
    values.set(hash, leak.secret)
  }
  while (values.size > VALUES_KEPT) values.delete(values.keys().next().value ?? '')
  await update($, entries, list => {
    let seq = list.at(-1)?.seq ?? 0
    const added: Entry[] = uniqueByHash(found).map(({ leak, hash }) => ({
      seq: ++seq,
      label: numbers[hash] ?? 0,
      at,
      source,
      rule: leak.rule,
      mask: mask(leak.secret),
      hash,
      decision,
      ...placeOf(leak),
    }))

    return [...list, ...added].slice(-MAX_ENTRIES)
  })
  await refreshStatus($)
}

async function recordFailure($: EngineInterface, source: string, reason: string, decision: Decision): Promise<void> {
  const at = await $.clock.now()
  await update($, entries, list => {
    const seq = (list.at(-1)?.seq ?? 0) + 1
    const row: Entry = { seq, label: 0, at, source, rule: t.unavailable, mask: reason, hash: '', decision }

    return [...list, row].slice(-MAX_ENTRIES)
  })
  await refreshStatus($)
}

async function refreshStatus($: EngineInterface): Promise<void> {
  const state = await read($, scanner)
  if (state.status === 'missing') {
    $.ui.status(`secret-guard: ${state.detail}`)

    return
  }
  const hidden = (await read($, entries)).filter(one => HIDING.has(one.decision)).length
  $.ui.status(hidden > 0 ? t.status(hidden) : undefined)
}

// --- the pane ---------------------------------------------------------------

async function drawPane($: EngineInterface, e: EventOf['ui.render']) {
  const { Box, Text, Button } = $.ui.resolve(e)
  const journal = await read($, entries)
  const allowList = await read($, allowed)
  const state = await read($, scanner)
  const opened = new Set(await read($, expanded))
  const shownValues = new Set(await read($, revealed))
  const allowedHashes = new Set(allowList.map(one => one.hash))
  const width = Math.max(24, 'bodyColumns' in e.props && typeof e.props.bodyColumns === 'number' ? e.props.bodyColumns : 60)
  const shown = journal.slice(-50).reverse()

  const toggle = (seq: number) =>
    update($, expanded, list => (list.includes(seq) ? list.filter(one => one !== seq) : [...list, seq]))
  const hideValue = (seq: number) => update($, revealed, list => list.filter(one => one !== seq))
  const showValue = async (seq: number) => {
    await update($, revealed, list => (list.includes(seq) ? list : [...list, seq]))
    $.clock.after(REVEAL_MS, () => hideValue(seq))
  }
  const allowEntry = (entry: Entry) =>
    update($, allowed, list =>
      list.some(one => one.hash === entry.hash)
        ? list
        : [...list, { hash: entry.hash, rule: entry.rule, mask: entry.mask, reason: 'allowlisted' as const }],
    )
  const clear = async () => {
    await update($, entries, () => [])
    await update($, expanded, () => [])
    await update($, revealed, () => [])
    values.clear()
    await refreshStatus($)
  }

  const drawEntry = (entry: Entry) => {
    const isOpen = opened.has(entry.seq)
    const lines = entry.lines ?? []
    const hits = lines.filter(line => line.isHit)
    const firstHit = hits[0]?.n ?? 0
    const lastHit = hits.at(-1)?.n ?? 0
    const reach = isOpen ? Infinity : AROUND_CLOSED
    const window = lines.filter(line => line.n >= firstHit - reach && line.n <= lastHit + reach)
    const place =
      entry.line === undefined
        ? undefined
        : entry.file !== undefined && entry.isFileLine === true
          ? t.pane.at(entry.file, entry.line)
          : `${entry.file === undefined ? '' : `${entry.file} · `}${t.pane.textLine(entry.line)}`
    const title = `${isOpen ? '▾' : '▸'} ${clock(entry.at)}  ${entry.rule}${entry.label > 0 ? ` #${entry.label}` : ''}  ${entry.mask}`
    const legend = NOTHING.has(entry.decision) ? t.pane.legendNothing : SAW.has(entry.decision) ? t.pane.legendSaw : t.pane.legendRead
    const numberOf = (n: number) => (entry.isNumbered === true ? '' : `${String(n).padStart(4)}  `)
    const isUnread = NOTHING.has(entry.decision)
    const value = entry.hash === '' ? undefined : values.get(entry.hash)
    const isShown = shownValues.has(entry.seq) && value !== undefined

    return (
      <Box key={`entry-${entry.seq}`} flexDirection="column" marginTop={1}>
        <Button key={`open-${entry.seq}`} plain label={title} onPress={() => toggle(entry.seq)} />
        <Text wrap="wrap" color={CUT.has(entry.decision) ? 'success' : 'warning'}>
          {t.decisions[entry.decision]}
        </Text>
        {place !== undefined && <Text wrap={isOpen ? 'wrap' : 'truncate-middle'}>{place}</Text>}
        <Text wrap={isOpen ? 'wrap' : 'truncate-end'} dimColor>
          {isOpen ? `${t.pane.sourceLabel} ${entry.source}` : entry.source}
        </Text>
        {isOpen && entry.filePath !== undefined && (
          <Text wrap="wrap" dimColor>
            {t.pane.fileLabel} {entry.filePath}
          </Text>
        )}
        {entry.lines === undefined && entry.hash !== '' && (
          <Text wrap="wrap" dimColor>
            {t.pane.noPlace}
          </Text>
        )}
        {window.length > 0 && (
          <Box flexDirection="column" marginTop={1}>
            <Text wrap="wrap" dimColor>
              {legend}
            </Text>
            {window.map(line => (
              <Box key={`line-${entry.seq}-${line.n}`} flexDirection="column">
                <Text wrap={isOpen ? 'wrap' : 'truncate-end'} dimColor={!line.isHit} bold={line.isHit}>
                  {line.isHit ? '› ' : '  '}
                  {numberOf(line.n)}
                  {tidy(isUnread ? (line.inFile ?? line.text) : line.text)}
                </Text>
                {line.isHit && !isUnread && line.inFile !== undefined && (
                  <Text wrap={isOpen ? 'wrap' : 'truncate-end'} color="warning">
                    {'  '}
                    {entry.file === undefined ? t.pane.inText : t.pane.inFile} {tidy(line.inFile).trimStart()}
                  </Text>
                )}
              </Box>
            ))}
          </Box>
        )}
        {isShown && (
          <Box flexDirection="column" marginTop={1}>
            <Text wrap="wrap" color="warning" bold>
              {t.pane.valueLabel} {value}
            </Text>
            <Text wrap="wrap" dimColor>
              {t.pane.valueWarning}
            </Text>
          </Box>
        )}
        {entry.hash !== '' && (
          <Box flexDirection="row" gap={1} marginTop={isShown ? 0 : 1}>
            {value === undefined ? (
              <Text dimColor>{t.pane.valueGone}</Text>
            ) : (
              <Button
                key={`reveal-${entry.seq}`}
                label={isShown ? t.pane.hideValue : t.pane.showValue}
                onPress={() => (isShown ? hideValue(entry.seq) : showValue(entry.seq))}
              />
            )}
            {isOpen && ALLOWABLE.has(entry.decision) && !allowedHashes.has(entry.hash) && (
              <Button key={`allow-${entry.seq}`} label={t.pane.allowButton} onPress={() => allowEntry(entry)} />
            )}
          </Box>
        )}
      </Box>
    )
  }

  return (
    <Box flexDirection="column" width={width}>
      <Text wrap="wrap" color={state.status === 'missing' ? 'error' : 'success'}>
        {state.status === 'missing' ? state.detail : t.pane.scanner(state.detail || 'gitleaks')}
      </Text>
      <Text wrap="wrap" dimColor>
        {t.pane.intro}
      </Text>
      <Box flexDirection="row" marginTop={1} justifyContent="space-between">
        <Text bold>{t.pane.findings(journal.length)}</Text>
        {journal.length > 0 && <Button key="clear" label={t.pane.clear} onPress={clear} />}
      </Box>
      {shown.length === 0 && <Text dimColor>{t.pane.none}</Text>}
      {shown.map(drawEntry)}
      <Box marginTop={1}>
        <Text bold>{t.pane.allowlist(allowList.length)}</Text>
      </Box>
      {allowList.length === 0 && (
        <Text wrap="wrap" dimColor>
          {t.pane.allowEmpty}
        </Text>
      )}
      {allowList.map(one => (
        <Box key={`allowed-${one.hash}`} flexDirection="column" marginTop={1}>
          <Text wrap="wrap">
            {one.rule} {one.mask} · {one.reason === 'passed' ? t.pane.passed : t.pane.notSecret}
          </Text>
          <Button
            key={`forget-${one.hash}`}
            label={t.pane.forgetButton}
            onPress={() => update($, allowed, list => list.filter(other => other.hash !== one.hash))}
          />
        </Box>
      ))}
      <Box marginTop={1}>
        <Text wrap="wrap" dimColor>
          {t.pane.allowHint}
        </Text>
      </Box>
    </Box>
  )
}

/** A line as the pane draws it: tabs (a Read's numbering) as spaces. */
function tidy(text: string): string {
  return text.replace(/\t/g, '  ')
}

// --- small helpers ------------------------------------------------------------

function firstLine(text: string): string {
  return text.trim().split('\n')[0]?.slice(0, 200) ?? ''
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

