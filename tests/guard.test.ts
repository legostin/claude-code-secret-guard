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
  /** The environment each gitleaks scan ran with, and the text it read. */
  envs?: Record<string, string>[]
  scanned?: string[]
  /** Whether the project has a .gitleaks.toml, and what the person's environment holds. */
  hasProjectConfig?: boolean
  variables?: Record<string, string>
  /** What the plugin's store holds at the start, and every value written to it. */
  store?: Record<string, unknown>
  stored?: string[]
  /** Runs while the dialog is open, before it is answered. */
  whileAsked?: () => Promise<void>
  opened?: string[]
}

/** Stands for gitleaks, the dialog, a Bash run and the store beneath the plugin. */
function world(on: On, w: World, output: string) {
  const clock = mock.clock(on, { now: 1_760_000_000_000 })
  // The plugin's store, in memory, every value written kept for a test to read.
  const store = new Map<string, unknown>(Object.entries(w.store ?? {}))
  on('store.get', ($, e) => ({ value: store.get(e.key) }))
  on('store.set', ($, e) => {
    ;(w.stored ??= []).push(JSON.stringify(e.value))
    store.set(e.key, JSON.parse(JSON.stringify(e.value)))
    return { value: undefined }
  })
  on('store.delete', ($, e) => {
    store.delete(e.key)
    return { value: undefined }
  })
  on('store.keys', () => ({ value: [...store.keys()] }))
  on('session.id', () => ({ value: 'f00dcafe-1234-5678-9abc-def012345678' }))
  on('ui.open', ($, e) => {
    ;(w.opened ??= []).push(e.id)
    return { value: { isPlaced: true } }
  })
  mock.env(on, w.variables ?? {})
  on('fs.exists', () => ({ value: w.hasProjectConfig === true }))
  on('ui.status', () => ({ value: undefined }))
  on('ui.toast', () => ({ value: undefined }))
  on('process.run', ($, e) => {
    if (w.isScannerBroken) throw new Error('spawn gitleaks ENOENT')
    if (e.argv[1] === 'version') return { value: ran('8.30.1\n') }
    ;(w.envs ??= []).push({ ...(e.init?.env ?? {}) })
    ;(w.scanned ??= []).push(e.init?.stdin ?? '')

    return { value: ran(report(e.init?.stdin ?? '')) }
  })
  on('session.root', () => ({ value: '/project' }))
  on('tool.call', { tool: 'AskUserQuestion' }, async ($, e) => {
    const question = e.questions[0]?.question ?? ''
    w.questions.push(question)
    await w.whileAsked?.()
    if (w.answer === undefined) return { deny: 'The user dismissed the dialog' }

    return { result: { questions: e.questions, answers: { [question]: w.answer } }, text: `${question} → ${w.answer}` }
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

  return clock
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
  test('a finding shows file:line, the lines around, the line as read and as in the file', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    const read = Array.from({ length: 12 }, (_, i) =>
      i === 5 ? `     6\tGITHUB_TOKEN=${TOKEN}` : `     ${i + 1}\tLINE_${i + 1}=x`,
    ).join('\n')
    world(on, w, read)
    on('tool.call', { tool: 'Read' }, () => ({ result: { type: 'text', file: { content: read } }, text: read }))

    await $.tool.call({ tool: 'Read', file_path: '/project/config/.env' })
    const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'terminal', ...PANE })
    expect(await ui.find({ type: 'Text', text: /^config\/\.env:6$/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /As the model read it/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /› +6 +GITHUB_TOKEN=\[SECRET:github-pat#1\]/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /in the file: 6 +GITHUB_TOKEN=ghp_…\[40\]/ })).toBeDefined()
    // three lines each side before it is opened
    expect(await ui.find({ type: 'Text', text: /LINE_3=x/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /LINE_9=x/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /LINE_2=x/ })).toBeUndefined()

    await ui.press({ key: 'open-1' })
    expect(await ui.find({ type: 'Text', text: /File: \/project\/config\/\.env$/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /LINE_12=x/ })).toBeDefined()
    expect(await ui.find({ type: 'Button', key: 'allow-1' })).toBeDefined()
    expect(JSON.stringify(await ui.drawn())).not.toContain(TOKEN)
    await ui.unmount()
  })

  test('"show the value" shows it in the pane alone, and hides it again after 30 s', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    const clock = world(on, w, OUTPUT)
    const ran = await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'terminal', ...PANE })
    expect(JSON.stringify(await ui.drawn())).not.toContain(TOKEN)
    await ui.press({ key: 'reveal-1' })
    expect(await ui.find({ type: 'Text', text: new RegExp(`Value: ${TOKEN}`) })).toBeDefined()
    expect(JSON.stringify(ran)).not.toContain(TOKEN)

    await clock.advance(30_000)
    expect(JSON.stringify(await ui.drawn())).not.toContain(TOKEN)
    await ui.unmount()
  })

  test('a value cut before is journaled as cut again, not as asked', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    await $.tool.call({ tool: 'Bash', command: 'env' })

    const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'terminal', ...PANE })
    expect(await ui.find({ type: 'Text', text: /cut again/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /cut on your choice/ })).toBeDefined()
    await ui.unmount()
  })

  test('lists a finding by mask on every surface, and "allow from now on" allowlists it', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    for (const surface of ['terminal', 'desktop'] as const) {
      const ui = await $.ui.mount({ plugin: 'secret-guard', surface, ...PANE })
      const drawn = JSON.stringify(await ui.drawn())
      expect(await ui.find({ type: 'Button', key: 'open-1' })).toBeDefined()
      expect(drawn).toContain('github-pat #1  ghp_…[40]')
      expect(drawn).not.toContain(TOKEN)
      await ui.unmount()
    }

    const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'terminal', ...PANE })
    await ui.press({ key: 'open-1' })
    await ui.press({ key: 'allow-1' })
    expect(await ui.find({ type: 'Text', text: /marked not a secret: the model sees it/ })).toBeDefined()
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
    expect(await ui.find({ type: 'Text', text: /Журнал \(1\)/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /Секреты этой сессии \(1\)/ })).toBeDefined()
    await ui.unmount()
  })
})

describe('system prompt', () => {
  test('a secret in a section is cut, the guard note is added last', async ($, on) => {
    const w: World = { questions: [] }
    world(on, w, OUTPUT)
    on('prompt.compose', () => ({
      sections: [
        { id: 'intro', text: 'You are a helpful agent.', scope: 'shared' },
        { id: 'env', text: `Deploy token: ${TOKEN}`, scope: 'session' },
      ],
    }))

    const composed = await $.prompt.compose({
      model: 'claude-opus-5-5',
      promptModel: 'claude-opus-5-5',
      surfaces: ['terminal'],
      tools: ['Bash'],
      outputStyle: { name: 'default', isKeepingCodingInstructions: true },
      traits: [],
    })
    const text = JSON.stringify(composed)
    expect(text).not.toContain(TOKEN)
    expect(text).toContain('Deploy token: [SECRET:github-pat#1]')
    expect(composed.sections.at(-1)?.id).toBe('secret-guard')
    expect(w.questions).toHaveLength(0)
  })
})

describe('gitleaks rules', () => {
  test('a scan runs with the extra rules over the default set', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    const config = w.envs?.[0]?.GITLEAKS_CONFIG_TOML ?? ''
    expect(config).toContain('useDefault = true')
    expect(config).toContain('id = "password-after-keyword"')
    expect(config).toContain('id = "high-entropy-token"')
  })

  test('over the project\'s own .gitleaks.toml when it has one', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [], hasProjectConfig: true }
    world(on, w, OUTPUT)
    await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    expect(w.envs?.[0]?.GITLEAKS_CONFIG_TOML).toContain("path = '/project/.gitleaks.toml'")
  })

  test('entropyRule off leaves the entropy rule out', { options: { entropyRule: false } }, async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    const config = w.envs?.[0]?.GITLEAKS_CONFIG_TOML ?? ''
    expect(config).toContain('id = "password-after-keyword"')
    expect(config).not.toContain('id = "high-entropy-token"')
  })

  test('both off: gitleaks runs as it is', { options: { keywordRules: false, entropyRule: false } }, async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    expect(w.envs?.[0]?.GITLEAKS_CONFIG_TOML).toBeUndefined()
  })

  test("a GITLEAKS_CONFIG the person set is left to rule", async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [], variables: { GITLEAKS_CONFIG: '/etc/gitleaks.toml' } }
    world(on, w, OUTPUT)
    await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    expect(w.envs?.[0]?.GITLEAKS_CONFIG_TOML).toBeUndefined()
  })
})

/** The key of the first Button whose key starts with `prefix`. */
async function buttonKey(ui: { findAll: (q: { type: string }) => Promise<{ key: string | undefined }[]> }, prefix: string) {
  const found = (await ui.findAll({ type: 'Button' })).find(one => one.key?.startsWith(prefix))
  if (found?.key === undefined) throw new Error(`no button ${prefix}*`)

  return found.key
}

describe('registry of secrets', () => {
  test('each secret is listed once, with how often it was seen', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    await $.tool.call({ tool: 'Bash', command: 'env' })

    const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'terminal', ...PANE })
    expect(await ui.find({ type: 'Text', text: /Secrets this session \(1\)/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /cut without a question: the model never sees it/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /seen 2 times · last .*Bash: env/ })).toBeDefined()
    await ui.unmount()
  })

  test('clearing the log forgets nothing: the secret is still cut without a question', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'terminal', ...PANE })
    await ui.press({ key: 'clear' })
    expect(await ui.find({ type: 'Text', text: /Log \(0\)/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /Secrets this session \(1\)/ })).toBeDefined()
    await ui.unmount()

    const again = await $.tool.call({ tool: 'Bash', command: 'env' })
    expect(w.questions).toHaveLength(1)
    expect(JSON.stringify(again)).toContain('[SECRET:github-pat#1]')
  })

  test('forget: the next time the value appears, the person is asked again', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'terminal', ...PANE })
    await ui.press({ key: await buttonKey(ui, 'forget-') })
    expect(await ui.find({ type: 'Text', text: /Secrets this session \(0\)/ })).toBeDefined()
    await ui.unmount()

    await $.tool.call({ tool: 'Bash', command: 'env' })
    expect(w.questions).toHaveLength(2)
  })

  test('"cut again" takes a value off the allowlist: the model reads a placeholder again', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'terminal', ...PANE })
    await ui.press({ key: await buttonKey(ui, 'allow-secret-') })
    expect(JSON.stringify(await $.tool.call({ tool: 'Bash', command: 'env' }))).toContain(TOKEN)
    await ui.press({ key: await buttonKey(ui, 'cut-secret-') })
    await ui.unmount()

    expect(JSON.stringify(await $.tool.call({ tool: 'Bash', command: 'env' }))).not.toContain(TOKEN)
    expect(w.questions).toHaveLength(1)
  })

  test('forget all: every value is asked about again, and no number is given twice', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    const other = 'ghp_Zq7Xv3Lm9Np2Rt5Wy8Bc1Df4Gh6Jk0Ms3Qa7E'
    on('tool.call', { tool: 'Read' }, () => ({ result: { type: 'text', file: { content: `K=${other}` } }, text: `K=${other}` }))
    await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'terminal', ...PANE })
    await ui.press({ key: 'forget-all' })
    expect(await ui.find({ type: 'Text', text: /Secrets this session \(0\)/ })).toBeDefined()
    await ui.unmount()

    const read = await $.tool.call({ tool: 'Read', file_path: '/project/k.env' })
    expect(JSON.stringify(read)).toContain('[SECRET:github-pat#2]')
    await $.tool.call({ tool: 'Bash', command: 'env' })
    expect(w.questions).toHaveLength(3)
  })
})

describe('random words in a prompt', () => {
  test('a password typed with nothing around it raises the dialog and is cut', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    let entered = ''
    on('prompt.submit', ($, e) => {
      entered = e.text
      return { text: e.text }
    })

    await $.prompt.submit({ text: 'прод доступ Qx7mP2kw!!', wait: false, origin: { kind: 'composer' } })
    expect(w.questions[0]).toContain('random-word')
    expect(entered).toBe('прод доступ [SECRET:random-word#1]')
  })

  test('wordRule off: the prompt goes on as it is', { options: { wordRule: false } }, async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    let entered = ''
    on('prompt.submit', ($, e) => {
      entered = e.text
      return { text: e.text }
    })

    await $.prompt.submit({ text: 'прод доступ Qx7mP2kw!!', wait: false, origin: { kind: 'composer' } })
    expect(w.questions).toHaveLength(0)
    expect(entered).toBe('прод доступ Qx7mP2kw!!')
  })
})

describe('history across sessions', () => {
  const earlier = {
    history: [
      {
        id: 'beefbeef-0000:1',
        session: 'beefbeef-0000',
        project: 'shop',
        at: 1_759_000_000_000,
        label: 3,
        source: 'Bash: cat .env',
        rule: 'stripe-access-token',
        mask: 'sk_l…[40]',
        decision: 'redacted',
        file: '.env',
        line: 4,
        isFileLine: true,
        lines: [{ n: 4, text: 'STRIPE=[SECRET:stripe-access-token#3]', isHit: true }],
      },
    ],
  }

  test('the history tab shows this session and earlier ones, grouped, newest first', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [], store: earlier }
    world(on, w, OUTPUT)
    await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'terminal', ...PANE })
    await ui.press({ key: 'tab-history' })
    const headers = (await ui.findAll({ type: 'Text' })).map(one => one.text).filter(text => / · \d+ events?$/.test(text))
    expect(headers).toHaveLength(2)
    expect(headers[0]).toContain('project · f00dcafe (this session) · 1 event')
    expect(headers[1]).toContain('shop · beefbeef · 1 event')
    expect(await ui.find({ type: 'Text', text: /STRIPE=\[SECRET:stripe-access-token#3\]/ })).toBeDefined()
    expect(JSON.stringify(await ui.drawn())).not.toContain(TOKEN)
    await ui.unmount()
  })

  test('what is stored on disk holds no value and no hash', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    const written = (w.stored ?? []).join('\n')
    expect(written).toContain('github-pat')
    expect(written).not.toContain(TOKEN)
    expect(written).not.toContain('"hash"')
  })

  test('a session can be deleted from the history, and all of it cleared', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [], store: earlier }
    world(on, w, OUTPUT)
    await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'terminal', ...PANE })
    await ui.press({ key: 'tab-history' })
    await ui.press({ key: 'drop-session-beefbeef-0000' })
    expect(await ui.find({ type: 'Text', text: /shop · beefbeef/ })).toBeUndefined()
    expect(await ui.find({ type: 'Text', text: /this session/ })).toBeDefined()
    await ui.press({ key: 'clear-history' })
    expect(await ui.find({ type: 'Text', text: /No history yet/ })).toBeDefined()
    await ui.press({ key: 'tab-session' })
    expect(await ui.find({ type: 'Text', text: /Secrets this session \(1\)/ })).toBeDefined()
    await ui.unmount()
  })
})

describe('the guard\'s own marks', () => {
  test('placeholders and masks reach the scanner as spaces, lines and columns kept', async ($, on) => {
    const w: World = { questions: [] }
    world(on, w, OUTPUT)
    const text = 'пароль [SECRET:random-word#2]{w\nключ ghp_…[40] тут'
    await append($, w, text)

    const seen = w.scanned?.find(one => one.length === text.length) ?? ''
    expect(seen).not.toContain('SECRET:')
    expect(seen).not.toContain('…[40]')
    expect(seen.split('\n').map(line => line.length)).toEqual(text.split('\n').map(line => line.length))
  })

  test('the guard\'s own dialog is not scanned, and adds nothing to the registry', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    on('prompt.submit', ($, e) => ({ text: e.text }))
    await $.prompt.submit({ text: `use this token ${TOKEN} please`, wait: false, origin: { kind: 'composer' } })

    expect(w.questions).toHaveLength(1)
    expect(w.scanned?.some(one => one.includes('What should be sent?'))).toBe(false)
    const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'terminal', ...PANE })
    expect(await ui.find({ type: 'Text', text: /Secrets this session \(1\)/ })).toBeDefined()
    await ui.unmount()
  })
})

describe('while the dialog is open', () => {
  test('the pane opens and shows where the secret stands, value masked; gone once answered', async ($, on) => {
    const read = ['     1\t# settings', `     2\tGITHUB_TOKEN=${TOKEN}`, '     3\tDEBUG=1'].join('\n')
    let drawnWhileAsked = ''
    const w: World = {
      answer: 'Cut the secrets',
      questions: [],
      whileAsked: async () => {
        const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'terminal', ...PANE })
        drawnWhileAsked = JSON.stringify(await ui.drawn())
        await ui.unmount()
      },
    }
    world(on, w, read)
    on('tool.call', { tool: 'Read' }, () => ({ result: { type: 'text', file: { content: read } }, text: read }))

    await $.tool.call({ tool: 'Read', file_path: '/project/config/.env' })
    expect(w.opened).toContain('secret-guard')
    expect(drawnWhileAsked).toContain('Waiting for your answer in the dialog')
    expect(drawnWhileAsked).toContain('config/.env:2')
    expect(drawnWhileAsked).toContain('GITHUB_TOKEN=ghp_…[40]')
    expect(drawnWhileAsked).toContain('DEBUG=1')
    expect(drawnWhileAsked).not.toContain(TOKEN)

    const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'terminal', ...PANE })
    expect(JSON.stringify(await ui.drawn())).not.toContain('Waiting for your answer')
    await ui.unmount()
  })
})

describe('a shell command typed with !', () => {
  test('runs as typed: nothing in it is cut or asked about', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    let entered = ''
    on('prompt.submit', ($, e) => {
      entered = e.text
      return { text: e.text }
    })

    const command = `! grep '^ACME_DB_PASS=' .env && echo Qx7mP2kw!! ${TOKEN}`
    await $.prompt.submit({ text: command, wait: false, origin: { kind: 'composer' } })
    expect(entered).toBe(command)
    expect(w.questions).toHaveLength(0)
  })

  test('a variable name in a prompt is no secret: only values are cut', async ($, on) => {
    const w: World = { answer: 'Cut the secrets', questions: [] }
    world(on, w, OUTPUT)
    let entered = ''
    on('prompt.submit', ($, e) => {
      entered = e.text
      return { text: e.text }
    })

    await $.prompt.submit({ text: "найди где читается ^ACME_DB_PASS= и STRIPE_SECRET_KEY", wait: false, origin: { kind: 'composer' } })
    expect(entered).toBe("найди где читается ^ACME_DB_PASS= и STRIPE_SECRET_KEY")
    expect(w.questions).toHaveLength(0)
  })
})
