// Every word the guard shows. What the model reads is English whatever the
// language; what the person reads follows the `language` option. Pure: no
// engine calls.

import type { Decision } from '../types'
import { mask, uniqueByHash } from './redact'
import type { Found } from './redact'

export type Lang = 'en' | 'ru'

// --- what the model reads ----------------------------------------------------

/** The section the model reads in its system prompt while the guard is on. */
export const NOTE = [
  'secret-guard is active: a scanner (gitleaks) checks tool outputs, prompts and attachments before you read them.',
  'Secrets it finds are replaced with placeholders like [SECRET:github-pat#1], or a whole tool output is withheld by the user.',
  'Treat placeholders as opaque. Do not try to recover a withheld value: no re-reading, encoding, splitting or printing parts of it.',
  'If a task needs a secret, use it indirectly (an environment variable, a file a command reads) or ask the user.',
].join('\n')

/** What the model reads in place of a tool output the person withheld. */
export function hiddenNote(tool: string, found: readonly Found[]): string {
  const rules = [...new Set(found.map(one => one.leak.rule))].join(', ')

  return [
    `secret-guard: the user withheld this ${tool} output from you: it contains secrets (${rules}).`,
    'Do not try to obtain these values another way. If the task needs one, ask the user.',
  ].join(' ')
}

/** What the model reads in place of a text the scanner could not check. */
export function withheld(reason: string): string {
  return `[secret-guard: text withheld, it could not be checked for secrets (${reason})]`
}

/**
 * What the model reads in place of a text withheld because gitleaks is not
 * installed: how to install it, so the agent can, and then try again.
 */
export const MISSING_NOTE = [
  '[secret-guard: text withheld. gitleaks, the secret scanner, is not installed, so nothing can be checked.',
  'Install it, then run this step again:',
  'macOS `brew install gitleaks`;',
  'Linux a release binary from https://github.com/gitleaks/gitleaks/releases into ~/.local/bin,',
  'or `go install github.com/zricethezav/gitleaks/v8@latest`.]',
].join(' ')

export const TOOL_FAILED = 'secret-guard: the output could not be checked for secrets and was withheld.'
export const MENTION_SKIPPED = 'secret-guard: the file holds secrets; the user chose not to attach it'
export const MENTION_FAILED = 'secret-guard: the file could not be checked for secrets'

// --- what the person reads ---------------------------------------------------

export type Texts = {
  header: string
  toolOptions: { redact: string; hide: string; pass: string; allow: string }
  promptOptions: { redact: string; send: string; cancel: string; allow: string }
  mentionOptions: { redact: string; skip: string; pass: string; allow: string }
  failureOptions: { hide: string; pass: string }
  missingOptions: { install: string; hide: string; pass: string }
  missingQuestion: (source: string) => string
  aborted: string
  installing: string
  installed: string
  installFailed: (line: string) => string
  noBrew: string
  missingToast: string
  decisions: Record<Decision, string>
  doors: Record<string, string>
  toolQuestion: (source: string, found: readonly Found[]) => string
  promptQuestion: (found: readonly Found[]) => string
  mentionQuestion: (source: string, found: readonly Found[]) => string
  failureQuestion: (source: string, reason: string) => string
  prompt: string
  shellCommand: string
  subagentPrefix: string
  subagentSuffix: string
  attachment: (type: string, file?: string) => string
  context: (name: string) => string
  systemPrompt: (section: string) => string
  promptDropped: string
  promptDroppedFailure: (reason: string) => string
  promptFailed: string
  mentionSkipped: (source: string) => string
  autoCut: (rule: string, source: string) => string
  withheldToast: (source: string) => string
  missing: string
  notFound: string
  exited: (code: number, line: string) => string
  unreadable: (message: string) => string
  unavailable: string
  status: (hidden: number) => string
  commandDescription: string
  paneOpened: string
  pane: {
    scanner: (detail: string) => string
    intro: string
    findings: (count: number) => string
    none: string
    at: (file: string, line: number) => string
    textLine: (line: number) => string
    legendRead: string
    legendSaw: string
    legendNothing: string
    inFile: string
    inText: string
    sourceLabel: string
    fileLabel: string
    noPlace: string
    showValue: string
    hideValue: string
    valueLabel: string
    valueWarning: string
    valueGone: string
    clear: string
    secrets: (count: number) => string
    secretsHint: string
    logHint: string
    statusCut: string
    statusNew: string
    statusPassed: string
    statusAllowed: string
    seen: (count: number) => string
    last: (time: string, source: string) => string
    forgetAll: string
    cutButton: string
    tabSession: string
    pendingTitle: string
    pendingLegend: string
    tabHistory: string
    historyHint: string
    historyNone: string
    clearHistory: string
    dropSession: string
    sessionHeader: (date: string, project: string, session: string, count: number, isThis: boolean) => string
    allowButton: string
    installButton: string
    forgetButton: string
  }
}

// What the engine's attachment kinds are, in the person's words.
const ATTACHMENTS_EN: Record<string, string> = {
  edited_text_file: 'changed file',
  file: 'attached file',
  nested_memory: 'CLAUDE.md',
  queued_command: 'queued prompt',
}

const ATTACHMENTS_RU: Record<string, string> = {
  edited_text_file: 'изменённый файл',
  file: 'приложенный файл',
  nested_memory: 'CLAUDE.md',
  queued_command: 'промпт из очереди',
}

const EN: Texts = {
  header: 'secret-guard',
  toolOptions: {
    redact: 'Cut the secrets',
    hide: 'Hide the whole output',
    pass: 'Let the model see it',
    allow: 'Not a secret, allow',
  },
  promptOptions: {
    redact: 'Cut the secrets',
    send: 'Send as is',
    cancel: 'Do not send',
    allow: 'Not a secret, allow',
  },
  mentionOptions: {
    redact: 'Cut the secrets',
    skip: 'Do not attach',
    pass: 'Attach as is',
    allow: 'Not a secret, allow',
  },
  failureOptions: { hide: 'Hide from the model', pass: 'Pass it unchecked' },
  missingOptions: { install: 'Install gitleaks and check', hide: 'Hide from the model', pass: 'Pass it unchecked' },
  missingQuestion: source => `gitleaks is not installed, so ${clip(source, 90)} cannot be checked. Install it now (brew install gitleaks)?`,
  aborted: 'the check was interrupted',
  installing: 'secret-guard: installing gitleaks (brew install gitleaks)…',
  installed: 'secret-guard: gitleaks installed, checks are on',
  installFailed: line => `gitleaks could not be installed: ${line}`,
  noBrew: 'Homebrew not found: install gitleaks by hand, https://github.com/gitleaks/gitleaks#installing',
  missingToast: 'secret-guard: gitleaks not found, nothing is checked. /secrets → install gitleaks',
  decisions: {
    redacted: 'cut on your choice',
    recut: 'cut again: this value was cut before, so no question',
    hidden: 'the whole output hidden from the model',
    passed: 'passed on your choice: the model saw the value',
    allowlisted: 'marked not a secret: the model saw the value',
    dropped: 'not sent to the model',
    'auto-redacted': 'cut without asking (text the engine adds on its own)',
    withheld: 'withheld whole: the scanner could not check it',
  },
  doors: {
    prompt: 'prompt',
  shellCommand: 'your ! command',
    command: 'command output',
    'tool-result': 'tool result',
    'tool-message': 'tool message',
    delivery: 'incoming message',
    attachment: 'attachment',
    'hook-context': 'hook context',
    note: 'plugin note',
  },
  toolQuestion: (source, found) => `${clip(source, 90)}: secrets found (${describe(found, 'en')}). What should the model see?`,
  promptQuestion: found => `Your prompt holds secrets (${describe(found, 'en')}). What should be sent?`,
  mentionQuestion: (source, found) => `${source} holds secrets (${describe(found, 'en')}). What should be attached?`,
  failureQuestion: (source, reason) => `secret-guard could not check ${source} (${reason}). Pass it to the model unchecked?`,
  prompt: 'prompt',
  shellCommand: 'your ! command',
  subagentPrefix: 'subagent, ',
  subagentSuffix: ' (subagent)',
  attachment: (type, file) => `${ATTACHMENTS_EN[type] ?? `system note (${type})`}${file === undefined ? '' : ` ${file}`}`,
  context: name => `context ${name}`,
  systemPrompt: section => `system prompt (${section})`,
  promptDropped: 'secret-guard: the prompt was not sent, it holds a secret. Its text is back in the input box.',
  promptDroppedFailure: reason => `secret-guard: the prompt was not sent, it could not be checked (${reason}).`,
  promptFailed: 'secret-guard: the prompt could not be checked for secrets and was not sent.',
  mentionSkipped: source => `secret-guard: ${source} was not attached`,
  autoCut: (rule, source) => `secret-guard: cut ${rule} (${source})`,
  withheldToast: source => `secret-guard: ${source} withheld, the scanner is unavailable`,
  missing: 'gitleaks not found: brew install gitleaks',
  notFound: 'gitleaks not found (brew install gitleaks)',
  exited: (code, line) => `gitleaks exited with ${code}: ${line}`,
  unreadable: message => `could not read the gitleaks report: ${message}`,
  unavailable: 'scanner unavailable',
  status: hidden => `secret-guard: ${hidden} hidden · /secrets`,
  commandDescription: 'secret-guard: secrets found, decisions and the allowlist',
  paneOpened: 'secret-guard pane opened.',
  pane: {
    scanner: detail => `Scanner: ${detail}`,
    intro: 'Secrets caught on their way to the model. Nothing in this pane is sent to it. Press a log entry to open it.',
    findings: count => `Log (${count})`,
    none: 'Nothing found yet.',
    at: (file, line) => `${file}:${line}`,
    textLine: line => `line ${line} of the text`,
    legendRead: 'As the model read it (› the line with the secret):',
    legendSaw: 'The model saw the value; here it is masked (› the line with the secret):',
    legendNothing: 'The model read none of this; the text was, values masked (› the line with the secret):',
    inFile: 'in the file:',
    inText: 'in the text:',
    sourceLabel: 'Source:',
    fileLabel: 'File:',
    noPlace: 'Recorded by an earlier version: no file or lines kept.',
    showValue: 'show the value',
    hideValue: 'hide the value',
    valueLabel: 'Value:',
    valueWarning: 'Only you see this pane; the model does not. It hides again in 30 s. Do not paste a screenshot of it into the chat: images reach the model and are not checked.',
    valueGone: 'value not kept (the mod reloaded)',
    clear: 'clear the journal',
    secrets: count => `Secrets this session (${count})`,
    secretsHint: 'Each value met, once. Forget it and you are asked again the next time it appears.',
    logHint: 'What happened, newest first. Clearing it forgets nothing: known secrets stay known.',
    statusCut: 'cut without a question: the model never sees it',
    statusNew: 'not cut yet: you are asked when it appears',
    statusPassed: 'passed by you: the model sees it',
    statusAllowed: 'marked not a secret: the model sees it',
    seen: count => `seen ${count} ${count === 1 ? 'time' : 'times'}`,
    last: (time, source) => `last ${time}, ${source}`,
    forgetAll: 'forget all',
    cutButton: 'cut again',
    tabSession: 'This session',
    pendingTitle: 'Waiting for your answer in the dialog',
    pendingLegend: 'The model has read none of this yet; the text, values masked (› the line with the secret):',
    tabHistory: 'All history',
    historyHint: 'Every session on this machine, newest first, up to 400 events. Kept on disk: masks and the lines around, never a value or a hash.',
    historyNone: 'No history yet.',
    clearHistory: 'clear all history',
    dropSession: 'delete',
    sessionHeader: (date, project, session, count, isThis) =>
      `${date} · ${project} · ${session}${isThis ? ' (this session)' : ''} · ${count} ${count === 1 ? 'event' : 'events'}`,
    allowButton: 'allow from now on',
    installButton: 'install gitleaks',
    forgetButton: 'forget',
  },
}

const RU: Texts = {
  header: 'secret-guard',
  toolOptions: {
    redact: 'Вырезать секреты',
    hide: 'Скрыть весь вывод',
    pass: 'Пропустить к модели',
    allow: 'Не секрет, пропускать',
  },
  promptOptions: {
    redact: 'Вырезать секреты',
    send: 'Отправить как есть',
    cancel: 'Не отправлять',
    allow: 'Не секрет, пропускать',
  },
  mentionOptions: {
    redact: 'Вырезать секреты',
    skip: 'Не прикладывать файл',
    pass: 'Приложить как есть',
    allow: 'Не секрет, пропускать',
  },
  failureOptions: { hide: 'Скрыть от модели', pass: 'Пропустить без проверки' },
  missingOptions: { install: 'Установить gitleaks и проверить', hide: 'Скрыть от модели', pass: 'Пропустить без проверки' },
  missingQuestion: source => `gitleaks не установлен, ${clip(source, 90)} нечем проверить. Установить сейчас (brew install gitleaks)?`,
  aborted: 'проверка прервана',
  installing: 'secret-guard: устанавливаю gitleaks (brew install gitleaks)…',
  installed: 'secret-guard: gitleaks установлен, проверка включена',
  installFailed: line => `не удалось установить gitleaks: ${line}`,
  noBrew: 'Homebrew не найден: установите gitleaks вручную, https://github.com/gitleaks/gitleaks#installing',
  missingToast: 'secret-guard: gitleaks не найден, проверка не работает. /secrets → установить gitleaks',
  decisions: {
    redacted: 'вырезан по вашему решению',
    recut: 'вырезан снова: это значение уже вырезалось, поэтому без вопроса',
    hidden: 'весь вывод скрыт от модели',
    passed: 'пропущен по вашему решению: модель видела значение',
    allowlisted: 'отмечен «не секрет»: модель видела значение',
    dropped: 'не отправлен модели',
    'auto-redacted': 'вырезан без вопроса (текст, который движок добавляет сам)',
    withheld: 'скрыт целиком: сканер не смог проверить',
  },
  doors: {
    prompt: 'промпт',
  shellCommand: 'ваша команда через !',
    command: 'вывод команды',
    'tool-result': 'результат инструмента',
    'tool-message': 'сообщение инструмента',
    delivery: 'входящее сообщение',
    attachment: 'вложение',
    'hook-context': 'контекст хука',
    note: 'запись плагина',
  },
  toolQuestion: (source, found) => `${clip(source, 90)}: найдены секреты (${describe(found, 'ru')}). Что отдать модели?`,
  promptQuestion: found => `В вашем промпте найдены секреты (${describe(found, 'ru')}). Что отправить модели?`,
  mentionQuestion: (source, found) => `В файле ${source} найдены секреты (${describe(found, 'ru')}). Что приложить к промпту?`,
  failureQuestion: (source, reason) => `secret-guard не смог проверить ${source} (${reason}). Отдать модели без проверки?`,
  prompt: 'промпт',
  shellCommand: 'ваша команда через !',
  subagentPrefix: 'субагент, ',
  subagentSuffix: ' (субагент)',
  attachment: (type, file) => `${ATTACHMENTS_RU[type] ?? `системная заметка (${type})`}${file === undefined ? '' : ` ${file}`}`,
  context: name => `контекст ${name}`,
  systemPrompt: section => `системный промпт (${section})`,
  promptDropped: 'secret-guard: промпт не отправлен, в нём секрет. Текст возвращён в поле ввода.',
  promptDroppedFailure: reason => `secret-guard: промпт не отправлен, проверка не удалась (${reason}).`,
  promptFailed: 'secret-guard: проверить промпт на секреты не удалось, промпт не отправлен.',
  mentionSkipped: source => `secret-guard: ${source} не приложен`,
  autoCut: (rule, source) => `secret-guard: вырезан ${rule} (${source})`,
  withheldToast: source => `secret-guard: ${source} скрыт, сканер недоступен`,
  missing: 'gitleaks не найден: brew install gitleaks',
  notFound: 'gitleaks не найден (brew install gitleaks)',
  exited: (code, line) => `gitleaks вернул код ${code}: ${line}`,
  unreadable: message => `не удалось разобрать отчёт gitleaks: ${message}`,
  unavailable: 'сканер недоступен',
  status: hidden => `secret-guard: скрыто ${hidden} · /secrets`,
  commandDescription: 'secret-guard: найденные секреты, решения и allowlist',
  paneOpened: 'Панель secret-guard открыта.',
  pane: {
    scanner: detail => `Сканер: ${detail}`,
    intro: 'Секреты, перехваченные по пути к модели. Ничего из этой панели модели не отправляется. Нажмите на запись журнала, чтобы раскрыть её.',
    findings: count => `Журнал (${count})`,
    none: 'Пока ничего не найдено.',
    at: (file, line) => `${file}:${line}`,
    textLine: line => `строка ${line} текста`,
    legendRead: 'Так это прочитала модель (› строка с секретом):',
    legendSaw: 'Модель видела значение; здесь оно замаскировано (› строка с секретом):',
    legendNothing: 'Модель ничего из этого не получила; текст был таким, значения замаскированы (› строка с секретом):',
    inFile: 'в файле:',
    inText: 'в тексте:',
    sourceLabel: 'Источник:',
    fileLabel: 'Файл:',
    noPlace: 'Записано прошлой версией: файл и строки не сохранены.',
    showValue: 'показать значение',
    hideValue: 'скрыть значение',
    valueLabel: 'Значение:',
    valueWarning: 'Эту панель видите только вы, модель её не получает. Через 30 с значение снова скроется. Не вставляйте скриншот панели в чат: картинки уходят модели и не проверяются.',
    valueGone: 'значение не сохранено (мод перезагружался)',
    clear: 'очистить журнал',
    secrets: count => `Секреты этой сессии (${count})`,
    secretsHint: 'Каждое встреченное значение, по одному разу. Если забыть значение, при следующем появлении снова спросит.',
    logHint: 'Что происходило, новое сверху. Очистка журнала ничего не забывает: известные секреты остаются известными.',
    statusCut: 'вырезается без вопроса: модель его не видит',
    statusNew: 'ещё не вырезался: при появлении спросит',
    statusPassed: 'пропущен вами: модель его видит',
    statusAllowed: 'отмечен «не секрет»: модель его видит',
    seen: count => `встречался ${count} ${timesRu(count)}`,
    last: (time, source) => `последний раз ${time}, ${source}`,
    forgetAll: 'забыть все',
    cutButton: 'снова вырезать',
    tabSession: 'Эта сессия',
    pendingTitle: 'Ждёт вашего ответа в диалоге',
    pendingLegend: 'Модель ещё ничего из этого не получила; текст, значения замаскированы (› строка с секретом):',
    tabHistory: 'Вся история',
    historyHint: 'Все сессии на этой машине, новые сверху, до 400 событий. Хранится на диске: маски и строки вокруг, никогда не значения и не хэши.',
    historyNone: 'Истории пока нет.',
    clearHistory: 'очистить всю историю',
    dropSession: 'удалить',
    sessionHeader: (date, project, session, count, isThis) =>
      `${date} · ${project} · ${session}${isThis ? ' (эта сессия)' : ''} · ${count} ${eventsRu(count)}`,
    allowButton: 'пропускать дальше',
    installButton: 'установить gitleaks',
    forgetButton: 'забыть',
  },
}

export function textsFor(language: unknown): Texts {
  return language === 'ru' ? RU : EN
}

/** The secrets of a dialog: rule and mask, three at most. */
export function describe(found: readonly Found[], lang: Lang): string {
  const distinct = uniqueByHash(found)
  const shown = distinct.slice(0, 3).map(({ leak }) => `${leak.rule} ${mask(leak.secret)}`)
  const rest = distinct.length - 3
  const more = rest > 0 ? (lang === 'ru' ? ` и ещё ${rest}` : ` and ${rest} more`) : ''

  return `${shown.join(', ')}${more}`
}

/** A tool call as the dialog and the journal name it: `Bash: cat .env`. */
export function describeCall(tool: string, input: Record<string, unknown>, prefix: string): string {
  const detail = [input.command, input.file_path, input.url, input.pattern, input.path].find(
    value => typeof value === 'string' && value !== '',
  ) as string | undefined
  return `${prefix}${tool}${detail === undefined ? '' : `: ${detail}`}`
}

/** The key an answer was given for, or the fallback for anything else. */
export function keyOf<O extends Record<string, string>>(
  labels: O,
  answer: string,
  fallback: keyof O & string,
): keyof O & string {
  return (Object.keys(labels) as (keyof O & string)[]).find(key => labels[key] === answer) ?? fallback
}

export function clock(at: number): string {
  return new Date(at).toTimeString().slice(0, 8)
}

/** The first absolute path a text names, as a changed-file note does. */
export function pathIn(text: string): string | undefined {
  const match = /(?:^|[\s'"`(])(\/[^\s'"`()]+)/.exec(text)

  return match?.[1]?.replace(/[.,:;]+$/, '')
}

/** A path as the pane shows it: under the project root relative, elsewhere whole. */
export function shortPath(path: string, root: string): string {
  return root !== '' && path.startsWith(`${root}/`) ? path.slice(root.length + 1) : path
}

/** A text cut to `max` characters, for a dialog's one line. */
export function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}

/** «раз» or «раза», as Russian counts times. */
function timesRu(count: number): string {
  const ten = count % 10
  const hundred = count % 100

  return ten >= 2 && ten <= 4 && (hundred < 12 || hundred > 14) ? 'раза' : 'раз'
}

/** «событие», «события» or «событий», as Russian counts events. */
function eventsRu(count: number): string {
  const ten = count % 10
  const hundred = count % 100
  if (ten === 1 && hundred !== 11) return 'событие'

  return ten >= 2 && ten <= 4 && (hundred < 12 || hundred > 14) ? 'события' : 'событий'
}

/** A day and time, as the history groups sessions: `07.10 11:42`. */
export function stamp(at: number): string {
  const date = new Date(at)
  const two = (n: number) => String(n).padStart(2, '0')

  return `${two(date.getDate())}.${two(date.getMonth() + 1)} ${two(date.getHours())}:${two(date.getMinutes())}`
}
