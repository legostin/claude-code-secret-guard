/**
 * What became of a secret the scanner found.
 *
 * - `redacted`: cut out on the person's choice
 * - `recut`: cut again without asking, a value cut before
 * - `hidden`: the whole tool output withheld on the person's choice
 * - `passed`: shown to the model on the person's choice
 * - `allowlisted`: marked as no secret, passed from now on
 * - `dropped`: the prompt was not sent, or the file not attached
 * - `auto-redacted`: cut out where no dialog could be shown
 * - `withheld`: the scanner failed and the text was withheld
 */
export type Decision =
  | 'redacted'
  | 'recut'
  | 'hidden'
  | 'passed'
  | 'allowlisted'
  | 'dropped'
  | 'auto-redacted'
  | 'withheld'

/**
 * One row of the pane's journal. Never holds a secret: `mask` shows at most
 * its first four characters and its length, `hash` is a SHA-256 prefix.
 */
export type Entry = {
  seq: number
  /** The number the model reads in `[SECRET:<rule>#<label>]`; 0 for none. */
  label: number
  at: number
  source: string
  rule: string
  mask: string
  hash: string
  decision: Decision
  /** The file the secret stood in, when the text says which: under the project root relative. */
  file?: string
  /** The same file's path as the text gave it, whole. */
  filePath?: string
  /** Its line: in `file` when `isFileLine`, else in the text that was checked. */
  line?: number
  isFileLine?: boolean
  /** The lines carry their own numbers (a Read's, a Grep's); else `n` numbers them. */
  isNumbered?: boolean
  /**
   * The lines around it: `text` as the model read it (placeholders where it
   * read none, masks where it saw the value), `inFile` as the text holds it
   * with the value masked, where the two differ; `n` the line in the text.
   */
  lines?: { n: number; text: string; isHit: boolean; inFile?: string }[]
}

/**
 * A secret met this session. Whether the model may read it is the allowlist's
 * to say (`allowed`); one with a `number` was cut and is cut again without a
 * question until the person forgets it.
 */
export type Known = {
  hash: string
  /** The number in `[SECRET:<rule>#<number>]`; 0 for a secret never cut. */
  number: number
  rule: string
  mask: string
  firstAt: number
  lastAt: number
  /** How many times it was journaled. */
  seen: number
  lastSource: string
}

/**
 * One event of the history kept across sessions, in the plugin's store on
 * disk: a journal row with no hash (a short secret's hash could be brute
 * forced) and its lines cut down to the ones around the secret.
 */
export type HistoryEntry = Omit<Entry, 'hash' | 'seq'> & {
  id: string
  session: string
  project: string
}

/** A secret the model may read: passed once, or marked as no secret. */
export type Allowed = {
  hash: string
  rule: string
  mask: string
  reason: 'passed' | 'allowlisted'
}

export type Scanner = {
  status: 'unknown' | 'ok' | 'missing'
  detail: string
}

declare module 'claude-code' {
  interface PluginState {
    'secret-guard': {
      entries: Entry[]
      allowed: Allowed[]
      /** Every secret met this session, by hash: the registry the pane manages. */
      known: Record<string, Known>
      /** The last placeholder number given; never reused, a forgotten secret's included. */
      lastNumber: number
      scanner: Scanner
      /** The journal rows the person opened in the pane, by `seq`. */
      expanded: number[]
      /** The secrets whose value the person is shown right now, by hash. */
      revealed: string[]
      /** The pane's tab. */
      tab: 'session' | 'history'
      /** The history events the person opened, by id. */
      openedHistory: string[]
      /** Bumped whenever the stored history changes, so the pane draws it again. */
      historyVersion: number
    }
  }
}
