/**
 * What became of a secret the scanner found.
 *
 * - `redacted`: cut out on the person's choice (or again, a secret already cut)
 * - `hidden`: the whole tool output withheld on the person's choice
 * - `passed`: shown to the model on the person's choice
 * - `allowlisted`: marked as no secret, passed from now on
 * - `dropped`: the prompt was not sent, or the file not attached
 * - `auto-redacted`: cut out where no dialog could be shown
 * - `withheld`: the scanner failed and the text was withheld
 */
export type Decision =
  | 'redacted'
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
    }
  }
}
