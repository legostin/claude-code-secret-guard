import { describe, expect, mock, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'
import type { On } from 'claude-code'

// A fake gitleaks: finds ghp_ tokens, one finding per occurrence, as
// `gitleaks stdin --report-format json --report-path -` reports them.
const PATTERN = /ghp_[A-Za-z0-9]{36}/g

function report(text: string): string {
  const findings = text.split('\n').flatMap((line, index) =>
    [...line.matchAll(PATTERN)].map(match => ({
      RuleID: 'github-pat',
      Secret: match[0],
      Match: match[0],
      StartLine: index + 1,
      EndLine: index + 1,
      Tags: [],
    })),
  )

  return JSON.stringify(findings)
}

function ran(stdout: string) {
  return { exitCode: 0, stdout, stderr: '', isStdoutTruncated: false, isStderrTruncated: false }
}

type World = {
  answer?: string
  isScannerBroken?: boolean
  questions: string[]
  rows?: unknown[]
}

/** Stands for gitleaks, the dialog, a Bash run and the store beneath the plugin. */
function world(on: On, w: World, output: string): void {
  mock.clock(on, { now: 1_760_000_000_000 })
  on('ui.status', () => ({ value: undefined }))
  on('ui.toast', () => ({ value: undefined }))
  on('process.run', ($, e) => {
    if (w.isScannerBroken) throw new Error('spawn gitleaks ENOENT')
    if (e.argv[1] === 'version') return { value: ran('8.30.1\n') }

    return { value: ran(report(e.init?.stdin ?? '')) }
  })
  on('session.root', () => ({ value: '/project' }))
  on('tool.call', { tool: 'AskUserQuestion' }, ($, e) => {
    const question = e.questions[0]?.question ?? ''
    w.questions.push(question)
    if (w.answer === undefined) return { deny: 'The user dismissed the dialog' }

    return { result: { questions: e.questions, answers: { [question]: w.answer } } }
  })
  on('tool.call', { tool: 'Bash' }, () => ({
    result: { stdout: output, stderr: '', interrupted: false },
    text: output,
  }))
  // The bottom of session.append is the engine's store, which a test has
  // not: the row is read here, on its way down, as the plugin passed it on.
  on('session.append', ($, e, next) => {
    ;(w.rows ??= []).push(e.message)
    return next(e)
  })
}

/** Appends a row and answers it as the plugin passed it on to be stored. */
async function append($: Engine, w: World, text: string): Promise<string> {
  try {
    await $.session.append({
      message: { type: 'user', content: [{ type: 'text', text }] },
      door: 'note',
      origin: { kind: 'plugin', event: 'test' },
      uuid: `row-${(w.rows ?? []).length}`,
    })
  } catch {
    // nothing stores rows in a test; the row was read on its way down
  }
  return JSON.stringify(w.rows?.at(-1) ?? null)
}

const TOKEN = 'ghp_8x2LmQ7vN4pR9sT1wY6zA3bC5dE0fG2hJ4kM'
const PANE = {
  component: 'Pane',
  requestId: 'secret-guard',
  props: {
    title: 'secret-guard',
    isFocused: false,
    bodyColumns: 70,
    placement: 'dock',
    scroll: { offset: 0, bodyRows: 40 },
    view: {},
  },
  viewport: { columns: 160, rows: 48 },
} as const
const OUTPUT = `GITHUB_TOKEN=${TOKEN}\nDEBUG=1`

describe('tool output', () => {
  test('"Вырезать секреты": the stored row carries a placeholder, never the token', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)

    const ran = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    expect(ran.deny).toBeUndefined()
    expect(JSON.stringify(ran.result)).toContain('GITHUB_TOKEN=[SECRET:github-pat#1]')
    expect(JSON.stringify(ran)).not.toContain(TOKEN)
    expect(w.questions).toHaveLength(1)
    expect(w.questions[0]).toContain('github-pat')
    expect(w.questions[0]).not.toContain(TOKEN)

    const row = await append($, w, OUTPUT)
    expect(row).not.toContain(TOKEN)
    expect(row).toContain('[SECRET:github-pat#1]')
  })

  test('"Скрыть весь вывод": the model gets a refusal without the token', async ($, on) => {
    const w: World = { answer: 'Hide the whole output', questions: [] }
    world(on, w, OUTPUT)

    const ran = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    expect(ran.deny).toContain('withheld')
    expect(ran.deny).not.toContain(TOKEN)
  })

  test('a dismissed dialog hides the output', async ($, on) => {
    const w: World = { questions: [] }
    world(on, w, OUTPUT)

    const ran = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    expect(ran.deny).toContain('withheld')
  })

  test('"Пропустить к модели": the token reaches the model, and is not asked about again', async ($, on) => {
    const w: World = { answer: 'Let the model see it', questions: [] }
    world(on, w, OUTPUT)

    const ran = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    expect(ran.text).toContain(TOKEN)
    expect(await append($, w, OUTPUT)).toContain(TOKEN)

    await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    expect(w.questions).toHaveLength(1)
  })

  test('a secret cut once is cut again without asking', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)

    await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    const again = await $.tool.call({ tool: 'Bash', command: 'env' })
    expect(w.questions).toHaveLength(1)
    expect(JSON.stringify(again)).not.toContain(TOKEN)
    expect(JSON.stringify(again)).toContain('[SECRET:github-pat#1]')
  })

  test('output with no secret passes without a dialog', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, 'hello world, nothing here')

    const ran = await $.tool.call({ tool: 'Bash', command: 'echo hi' })
    expect(ran.text).toBe('hello world, nothing here')
    expect(w.questions).toHaveLength(0)
  })
})

describe('scanner failure', () => {
  test('the person is asked; "Скрыть от модели" withholds the output', async ($, on) => {
    const w: World = { answer: 'Hide from the model', isScannerBroken: true, questions: [] }
    world(on, w, OUTPUT)

    const ran = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    expect(ran.deny).toContain('secret-guard')
    expect(w.questions[0]).toContain('could not check')
  })

  test('"Пропустить без проверки" lets the output on, and its row is not withheld', async ($, on) => {
    const w: World = { answer: 'Pass it unchecked', isScannerBroken: true, questions: [] }
    world(on, w, OUTPUT)

    const ran = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    expect(ran.text).toBe(OUTPUT)
    const row = await append($, w, OUTPUT)
    expect(row).toContain('DEBUG=1')
    expect(row).not.toContain('withheld')
  })

  test('a row no dialog was shown for is withheld whole', async ($, on) => {
    const w: World = { isScannerBroken: true, questions: [] }
    world(on, w, OUTPUT)

    expect(await append($, w, 'some text 12345')).toContain('text withheld')
    expect(w.questions).toHaveLength(0)
  })
})

describe('prompt', () => {
  test('"Вырезать секреты": the prompt enters with a placeholder', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    let entered = ''
    on('prompt.submit', ($, e) => {
      entered = e.text
      return { text: e.text }
    })

    await $.prompt.submit({ text: `use this token ${TOKEN} please`, wait: false, origin: { kind: 'composer' } })
    expect(entered).toBe('use this token [SECRET:github-pat#1] please')
    expect(w.questions[0]).toContain('Your prompt')
  })

  test('"Не отправлять": nothing enters', async ($, on) => {
    const w: World = { answer: 'Do not send', questions: [] }
    world(on, w, OUTPUT)
    let isEntered = false
    on('prompt.submit', ($, e) => {
      isEntered = true
      return { text: e.text }
    })
    let refilled = ''
    on('prompt.fill', ($, e) => {
      refilled = e.text
      return { isFilled: true, text: e.text, cursor: e.text.length }
    })

    const result = await $.prompt.submit({ text: `token ${TOKEN}`, wait: false, origin: { kind: 'composer' } })
    expect(isEntered).toBe(false)
    expect(JSON.stringify(result)).toContain('not sent')
    expect(refilled).toBe(`token ${TOKEN}`)
  })
})

describe('pane', () => {
  test('lists a finding by mask, and "не секрет" allowlists it', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    for (const surface of ['terminal', 'desktop'] as const) {
      const ui = await $.ui.mount({ plugin: 'secret-guard', surface, ...PANE })
      expect(await ui.find({ type: 'Text', text: /github-pat #1/ })).toBeDefined()
      expect(JSON.stringify(await ui.find({ type: 'Text', text: /ghp_…\[40\]/ }))).not.toContain(TOKEN)
      await ui.unmount()
    }

    const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'terminal', ...PANE })
    await ui.press({ key: 'allow-1' })
    expect(await ui.find({ type: 'Text', text: /Allowlist \(1\)/ })).toBeDefined()
    await ui.unmount()
  })
})


describe('language', () => {
  test('ru: the dialog and the pane speak Russian, the model still reads English', { options: { language: 'ru' } }, async ($, on) => {
    const w: World = { answer: 'Скрыть весь вывод', questions: [] }
    world(on, w, OUTPUT)

    const ran = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    expect(w.questions[0]).toContain('найдены секреты')
    expect(ran.deny).toContain('the user withheld')

    const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'terminal', ...PANE })
    expect(await ui.find({ type: 'Text', text: /Находки \(1\)/ })).toBeDefined()
    await ui.unmount()
  })
})
