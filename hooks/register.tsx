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

import type { Decision, Entry, HistoryEntry, Known } from '../types'
import { excerpt, hashOf, mapTexts, mask, parseReport, placeholder, redact, redactRecord, uniqueByHash, withoutOwnMarks } from './redact'
import { configWith } from './rules'
import { randomWords } from './words'
import type { RuleSet } from './rules'
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
  stamp,
  textsFor,
  TOOL_FAILED,
  withheld,
} from './texts'

const PANE = 'secret-guard'

const entries = atom({ plugin: 'secret-guard', key: 'entries' } as const, [])
const allowed = atom({ plugin: 'secret-guard', key: 'allowed' } as const, [])
const known = atom({ plugin: 'secret-guard', key: 'known' } as const, {})
const lastNumber = atom({ plugin: 'secret-guard', key: 'lastNumber' } as const, 0)
const scanner = atom({ plugin: 'secret-guard', key: 'scanner' } as const, { status: 'unknown', detail: '' })
const expanded = atom({ plugin: 'secret-guard', key: 'expanded' } as const, [])
const revealed = atom({ plugin: 'secret-guard', key: 'revealed' } as const, [])
const tab = atom({ plugin: 'secret-guard', key: 'tab' } as const, 'session')
const openedHistory = atom({ plugin: 'secret-guard', key: 'openedHistory' } as const, [])
const historyVersion = atom({ plugin: 'secret-guard', key: 'historyVersion' } as const, 0)

// The history kept across sessions, in the plugin's store.
const HISTORY_KEY = 'history'
const HISTORY_KEPT = 400
const HISTORY_SHOWN = 150

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
// The rules added to gitleaks' own (the keywordRules and entropyRule options),
// and the environment that hands them to gitleaks, by project root.
let ruleSet: RuleSet = { keywords: true, entropy: true }
// Random-looking words in the person's prompts (the wordRule option).
let isWordRuleOn = true
const environments = new Map<string, Record<string, string>>()

export const register: Register = (on, options) => {
  t = textsFor(options.language)
  ruleSet = { keywords: options.keywordRules !== false, entropy: options.entropyRule !== false }
  isWordRuleOn = options.wordRule !== false

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
    // The guard's own dialog: its question names masks, never a value.
    if (isOwnDialog(e as unknown as Record<string, unknown>)) return ran

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

    const leaks = isWordRuleOn ? withWords(result.leaks, e.text) : result.leaks
    const found = await unresolved($, leaks)
    if (found.length === 0) return next(e)
    const origin: Origin = { text: e.text, leaks }
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
  const env = await gitleaksEnvironment($, cwd)
  let reason = t.notFound
  for (const bin of gitleaks === undefined ? GITLEAKS_PATHS : [gitleaks]) {
    let ran
    try {
      ran = await $.process.run([bin, ...GITLEAKS_ARGS], { cwd, env, stdin: withoutOwnMarks(text), timeoutMs: 20_000 })
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

/**
 * The environment gitleaks runs in: the guard's rules, as GITLEAKS_CONFIG_TOML,
 * over the project's `.gitleaks.toml` when there is one (gitleaks would read
 * that file otherwise) and over the default set when not. A GITLEAKS_CONFIG
 * the person set outranks it, so then the guard adds nothing and theirs rules.
 */
async function gitleaksEnvironment($: EngineInterface, root: string): Promise<Record<string, string>> {
  const kept = environments.get(root)
  if (kept !== undefined) return kept
  let env: Record<string, string> = {}
  if ((ruleSet.keywords || ruleSet.entropy) && (await $.env.get('GITLEAKS_CONFIG')) === undefined) {
    const own = `${root}/.gitleaks.toml`
    const base = (await $.fs.exists(own)) ? own : undefined
    env = { GITLEAKS_CONFIG_TOML: configWith(base, ruleSet) }
  }
  environments.set(root, env)

  return env
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

/** An AskUserQuestion call the guard raised itself, by the header it gives its dialogs. */
function isOwnDialog(input: Record<string, unknown>): boolean {
  const questions = input.questions

  return (
    input.tool === 'AskUserQuestion' &&
    Array.isArray(questions) &&
    questions.some(one => (one as { header?: unknown } | null)?.header === t.header)
  )
}

/** gitleaks' leaks and the random-looking words it did not already cover. */
function withWords(leaks: readonly Leak[], text: string): Leak[] {
  const words = randomWords(text).filter(
    word => !leaks.some(leak => leak.secret.includes(word.secret) || word.secret.includes(leak.secret)),
  )

  return [...leaks, ...words]
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
  const registry = await read($, known)
  const isCut = (one: Found) => (registry[one.hash]?.number ?? 0) > 0

  return { known: found.filter(isCut), novel: found.filter(one => !isCut(one)) }
}

/**
 * Gives each secret the number the model reads it under, keeping the ones it
 * has. Numbers come from a counter that only grows, so a secret forgotten and
 * met again, or a new one after it, never takes a number the model has read
 * for another value.
 */
async function numbersFor($: EngineInterface, found: readonly Found[]): Promise<Record<string, number>> {
  const registry = await read($, known)
  const lacking = uniqueByHash(found).filter(one => (registry[one.hash]?.number ?? 0) === 0)
  if (lacking.length > 0) {
    let first = 0
    await update($, lastNumber, last => {
      first = last + 1

      return last + lacking.length
    })
    const at = await $.clock.now()
    await update($, known, current => {
      const next = { ...current }
      lacking.forEach(({ leak, hash }, index) => {
        const had = next[hash]
        if ((had?.number ?? 0) > 0) return
        next[hash] = had === undefined
          ? { hash, number: first + index, rule: leak.rule, mask: mask(leak.secret), firstAt: at, lastAt: at, seen: 0, lastSource: '' }
          : { ...had, number: first + index }
      })

      return next
    })
  }

  return numbersOf(await read($, known))
}

function numbersOf(registry: Record<string, Known>): Record<string, number> {
  const numbers: Record<string, number> = {}
  for (const one of Object.values(registry)) if (one.number > 0) numbers[one.hash] = one.number

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
  const numbers = numbersOf(await read($, known))
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
  await update($, known, current => {
    const next = { ...current }
    for (const { leak, hash } of uniqueByHash(found)) {
      const had = next[hash]
      next[hash] = {
        hash,
        number: had?.number ?? 0,
        rule: had?.rule ?? leak.rule,
        mask: had?.mask ?? mask(leak.secret),
        firstAt: had?.firstAt ?? at,
        lastAt: at,
        seen: (had?.seen ?? 0) + 1,
        lastSource: source,
      }
    }

    return next
  })
  let added: Entry[] = []
  await update($, entries, list => {
    let seq = list.at(-1)?.seq ?? 0
    added = uniqueByHash(found).map(({ leak, hash }) => ({
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
  await keepInHistory($, added)
  await refreshStatus($)
}

async function recordFailure($: EngineInterface, source: string, reason: string, decision: Decision): Promise<void> {
  const at = await $.clock.now()
  let row: Entry | undefined
  await update($, entries, list => {
    const seq = (list.at(-1)?.seq ?? 0) + 1
    row = { seq, label: 0, at, source, rule: t.unavailable, mask: reason, hash: '', decision }

    return [...list, row].slice(-MAX_ENTRIES)
  })
  await keepInHistory($, row === undefined ? [] : [row])
  await refreshStatus($)
}

/**
 * Adds journal rows to the history kept across sessions: no hash, and only
 * the lines around the secret. The history is a convenience: a store that
 * fails or is full loses the event, never a check.
 */
async function keepInHistory($: EngineInterface, rows: readonly Entry[]): Promise<void> {
  if (rows.length === 0) return
  const session = await $.session.id()
  const project = (await $.session.root()).split('/').filter(Boolean).at(-1) ?? ''
  const kept: HistoryEntry[] = rows.map(({ hash: _hash, seq, lines, ...row }) => ({
    ...row,
    id: `${session}:${seq}`,
    session,
    project,
    ...(lines === undefined ? {} : { lines: nearHits(lines) }),
  }))
  try {
    const before = asHistory(await $.store.get(HISTORY_KEY))
    await $.store.set(HISTORY_KEY, [...before, ...kept].slice(-HISTORY_KEPT))
  } catch {
    return
  }
  await update($, historyVersion, version => version + 1)
}

function asHistory(value: unknown): HistoryEntry[] {
  return Array.isArray(value) ? (value as HistoryEntry[]) : []
}

/** The lines within AROUND_CLOSED of the secret, each cut to 200 characters. */
function nearHits(lines: NonNullable<Entry['lines']>): NonNullable<Entry['lines']> {
  const hits = lines.filter(line => line.isHit).map(line => line.n)
  const from = Math.min(...hits) - AROUND_CLOSED
  const to = Math.max(...hits) + AROUND_CLOSED
  const clip = (text: string) => (text.length > 200 ? `${text.slice(0, 199)}…` : text)

  return lines
    .filter(line => line.n >= from && line.n <= to)
    .map(line => ({ ...line, text: clip(line.text), ...(line.inFile === undefined ? {} : { inFile: clip(line.inFile) }) }))
}

async function refreshStatus($: EngineInterface): Promise<void> {
  const state = await read($, scanner)
  if (state.status === 'missing') {
    $.ui.status(`secret-guard: ${state.detail}`)

    return
  }
  const passing = new Set((await read($, allowed)).map(one => one.hash))
  const hidden = Object.values(await read($, known)).filter(one => one.number > 0 && !passing.has(one.hash)).length
  $.ui.status(hidden > 0 ? t.status(hidden) : undefined)
}

// --- the pane ---------------------------------------------------------------

async function drawPane($: EngineInterface, e: EventOf['ui.render']) {
  const { Box, Text, Button } = $.ui.resolve(e)
  const journal = await read($, entries)
  const allowList = await read($, allowed)
  const registry = Object.values(await read($, known)).sort((a, b) => b.lastAt - a.lastAt)
  const state = await read($, scanner)
  const opened = new Set(await read($, expanded))
  const openedPast = new Set(await read($, openedHistory))
  const shownValues = new Set(await read($, revealed))
  const activeTab = await read($, tab)
  await read($, historyVersion)
  const allowedBy = new Map(allowList.map(one => [one.hash, one.reason]))
  const width = Math.max(24, 'bodyColumns' in e.props && typeof e.props.bodyColumns === 'number' ? e.props.bodyColumns : 60)
  const shown = journal.slice(-50).reverse()

  const toggle = (seq: number) =>
    update($, expanded, list => (list.includes(seq) ? list.filter(one => one !== seq) : [...list, seq]))
  const hideValue = (hash: string) => update($, revealed, list => list.filter(one => one !== hash))
  const showValue = async (hash: string) => {
    await update($, revealed, list => (list.includes(hash) ? list : [...list, hash]))
    $.clock.after(REVEAL_MS, () => hideValue(hash))
  }
  const allowHash = async (hash: string, rule: string, shownMask: string) => {
    await update($, allowed, list =>
      list.some(one => one.hash === hash) ? list : [...list, { hash, rule, mask: shownMask, reason: 'allowlisted' as const }],
    )
    await refreshStatus($)
  }
  const cutAgain = async (hash: string) => {
    await update($, allowed, list => list.filter(one => one.hash !== hash))
    await refreshStatus($)
  }
  const forget = async (hash: string) => {
    await update($, known, current => {
      const next = { ...current }
      delete next[hash]

      return next
    })
    await update($, allowed, list => list.filter(one => one.hash !== hash))
    await update($, revealed, list => list.filter(one => one !== hash))
    values.delete(hash)
    await refreshStatus($)
  }
  const forgetAll = async () => {
    await update($, known, () => ({}))
    await update($, allowed, () => [])
    await update($, revealed, () => [])
    values.clear()
    await refreshStatus($)
  }
  const clearLog = async () => {
    await update($, entries, () => [])
    await update($, expanded, () => [])
    await refreshStatus($)
  }

  const drawValue = (hash: string) => {
    const value = values.get(hash)
    if (value === undefined || !shownValues.has(hash)) return undefined

    return (
      <Box flexDirection="column" marginTop={1}>
        <Text wrap="wrap" color="warning" bold>
          {t.pane.valueLabel} {value}
        </Text>
        <Text wrap="wrap" dimColor>
          {t.pane.valueWarning}
        </Text>
      </Box>
    )
  }
  const revealButton = (hash: string, key: string) =>
    values.get(hash) === undefined ? (
      <Text dimColor>{t.pane.valueGone}</Text>
    ) : (
      <Button
        key={key}
        label={shownValues.has(hash) ? t.pane.hideValue : t.pane.showValue}
        onPress={() => (shownValues.has(hash) ? hideValue(hash) : showValue(hash))}
      />
    )

  const drawSecret = (one: Known) => {
    const passing = allowedBy.get(one.hash)
    const status = passing === undefined ? (one.number > 0 ? t.pane.statusCut : t.pane.statusNew) : passing === 'passed' ? t.pane.statusPassed : t.pane.statusAllowed

    return (
      <Box key={`secret-${one.hash}`} flexDirection="column" marginTop={1}>
        <Text wrap="wrap" bold>
          {one.rule}
          {one.number > 0 ? ` #${one.number}` : ''} {one.mask}
        </Text>
        <Text wrap="wrap" color={passing === undefined ? 'success' : 'warning'}>
          {status}
        </Text>
        <Text wrap="truncate-end" dimColor>
          {t.pane.seen(one.seen)} · {t.pane.last(clock(one.lastAt), one.lastSource)}
        </Text>
        {drawValue(one.hash)}
        <Box flexDirection="row" gap={1}>
          {revealButton(one.hash, `reveal-secret-${one.hash}`)}
          {passing === undefined ? (
            <Button key={`allow-secret-${one.hash}`} label={t.pane.allowButton} onPress={() => allowHash(one.hash, one.rule, one.mask)} />
          ) : (
            <Button key={`cut-secret-${one.hash}`} label={t.pane.cutButton} onPress={() => cutAgain(one.hash)} />
          )}
          <Button key={`forget-${one.hash}`} label={t.pane.forgetButton} onPress={() => forget(one.hash)} />
        </Box>
      </Box>
    )
  }

  const drawEntry = (entry: EntryView, key: string, isOpen: boolean, onToggle: () => unknown) => {
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
    const hash = entry.hash === undefined || entry.hash === '' ? undefined : entry.hash

    return (
      <Box key={`entry-${key}`} flexDirection="column" marginTop={1}>
        <Button key={`open-${key}`} plain label={title} onPress={onToggle} />
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
        {entry.lines === undefined && entry.rule !== t.unavailable && (
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
              <Box key={`line-${key}-${line.n}`} flexDirection="column">
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
        {hash !== undefined && drawValue(hash)}
        {hash !== undefined && (
          <Box flexDirection="row" gap={1} marginTop={1}>
            {revealButton(hash, `reveal-${key}`)}
            {isOpen && ALLOWABLE.has(entry.decision) && !allowedBy.has(hash) && (
              <Button key={`allow-${key}`} label={t.pane.allowButton} onPress={() => allowHash(hash, entry.rule, entry.mask)} />
            )}
          </Box>
        )}
      </Box>
    )
  }

  const tabs = (
    <Box flexDirection="row" gap={1} marginTop={1}>
      <Button
        key="tab-session"
        label={t.pane.tabSession}
        {...(activeTab === 'session' ? { variant: 'primary' as const } : {})}
        onPress={() => update($, tab, () => 'session' as const)}
      />
      <Button
        key="tab-history"
        label={t.pane.tabHistory}
        {...(activeTab === 'history' ? { variant: 'primary' as const } : {})}
        onPress={() => update($, tab, () => 'history' as const)}
      />
    </Box>
  )
  const header = (
    <Box flexDirection="column">
      <Text wrap="wrap" color={state.status === 'missing' ? 'error' : 'success'}>
        {state.status === 'missing' ? state.detail : t.pane.scanner(state.detail || 'gitleaks')}
      </Text>
      <Text wrap="wrap" dimColor>
        {t.pane.intro}
      </Text>
      {tabs}
    </Box>
  )

  if (activeTab === 'history') {
    const thisSession = await $.session.id()
    const past = asHistory(await $.store.get(HISTORY_KEY)).slice(-HISTORY_SHOWN)
    const sessions = new Map<string, HistoryEntry[]>()
    for (const one of past) sessions.set(one.session, [...(sessions.get(one.session) ?? []), one])
    const groups = [...sessions.values()].sort((a, b) => (b.at(-1)?.at ?? 0) - (a.at(-1)?.at ?? 0))
    const togglePast = (id: string) =>
      update($, openedHistory, list => (list.includes(id) ? list.filter(one => one !== id) : [...list, id]))
    const rewrite = async (keep: (one: HistoryEntry) => boolean) => {
      const all = asHistory(await $.store.get(HISTORY_KEY))
      await $.store.set(HISTORY_KEY, all.filter(keep))
      await update($, historyVersion, version => version + 1)
    }

    return (
      <Box flexDirection="column" width={width}>
        {header}
        <Box flexDirection="row" marginTop={1} justifyContent="space-between">
          <Text bold>{t.pane.tabHistory}</Text>
          {past.length > 0 && <Button key="clear-history" label={t.pane.clearHistory} onPress={() => rewrite(() => false)} />}
        </Box>
        <Text wrap="wrap" dimColor>
          {t.pane.historyHint}
        </Text>
        {groups.length === 0 && <Text dimColor>{t.pane.historyNone}</Text>}
        {groups.map(group => {
          const first = group[0]
          if (first === undefined) return undefined
          const session = first.session

          return (
            <Box key={`session-${session}`} flexDirection="column" marginTop={2}>
              <Box flexDirection="row" justifyContent="space-between">
                <Text wrap="wrap" bold color="accent">
                  {t.pane.sessionHeader(stamp(first.at), first.project, session.slice(0, 8), group.length, session === thisSession)}
                </Text>
                <Button key={`drop-session-${session}`} label={t.pane.dropSession} onPress={() => rewrite(one => one.session !== session)} />
              </Box>
              {[...group].reverse().map(one => drawEntry(one, `h-${one.id}`, openedPast.has(one.id), () => togglePast(one.id)))}
            </Box>
          )
        })}
      </Box>
    )
  }

  return (
    <Box flexDirection="column" width={width}>
      {header}

      <Box flexDirection="row" marginTop={1} justifyContent="space-between">
        <Text bold>{t.pane.secrets(registry.length)}</Text>
        {registry.length > 0 && <Button key="forget-all" label={t.pane.forgetAll} onPress={forgetAll} />}
      </Box>
      <Text wrap="wrap" dimColor>
        {t.pane.secretsHint}
      </Text>
      {registry.length === 0 && <Text dimColor>{t.pane.none}</Text>}
      {registry.map(drawSecret)}

      <Box flexDirection="row" marginTop={2} justifyContent="space-between">
        <Text bold>{t.pane.findings(journal.length)}</Text>
        {journal.length > 0 && <Button key="clear" label={t.pane.clear} onPress={clearLog} />}
      </Box>
      <Text wrap="wrap" dimColor>
        {t.pane.logHint}
      </Text>
      {shown.length === 0 && <Text dimColor>{t.pane.none}</Text>}
      {shown.map(entry => drawEntry(entry, String(entry.seq), opened.has(entry.seq), () => toggle(entry.seq)))}
    </Box>
  )
}

/** A journal row or a history event, as the pane draws either. */
type EntryView = Omit<Entry, 'hash' | 'seq'> & { hash?: string }

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

