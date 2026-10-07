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
      labels: Record<string, number>
      scanner: Scanner
      /** The journal rows the person opened in the pane, by `seq`. */
      expanded: number[]
      /** The journal rows whose value the person is shown right now, by `seq`. */
      revealed: number[]
    }
  }
}
