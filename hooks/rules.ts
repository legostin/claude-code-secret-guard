// Built by scripts/build_rules.py from rules/*.toml; edit those, then run it.
// scripts/check_rules.py checks the rules against real gitleaks.

/** Secrets after a keyword (EN/RU), in a URL, after Bearer, and sk-proj- keys. */
export const KEYWORD_RULES = [
  "[[rules]]",
  "id = \"password-after-keyword\"",
  "description = \"A password, secret or token written after a keyword, in English or Russian\"",
  "regex = '''(?i)(?:пароль|парол[яюеи]|password|passwd|passphrase|pwd|секрет|secret|токен|token|ключ доступа|access key)[\\p{L}_-]*(?:(?:[ \\t]+\\p{L}{1,15}){1,3}(?:[ \\t]*[:=][ \\t]*|[ \\t]+(?:—|–|-|is|это|равен)[ \\t]+)|(?:[ \\t]*[:=][ \\t]*|[ \\t]+(?:(?:—|–|-|is|это|равен)[ \\t]+)?))[\"'`]?([^\\s\"'`:=][^\\s\"'`]{5,})'''",
  "secretGroup = 1",
  "keywords = [\"пароль\", \"пароля\", \"паролю\", \"пароле\", \"пароли\", \"password\", \"passwd\", \"passphrase\", \"pwd\", \"секрет\", \"secret\", \"токен\", \"token\", \"ключ доступа\", \"access key\"]",
  "[[rules.allowlists]]",
  "regexTarget = \"secret\"",
  "regexes = [",
  "  '''^[\\p{L}_-]+[.,;:!?)]*$''',",
  "  '''[<>]''',",
  "  '''(?i)^(true|false|null|none|nil|undefined)\\W*$''',",
  "  '''^[0-9.,:/_-]+$''',",
  "  '''^(?:~|\\.{1,2})?/''',",
  "  '''^\\$[A-Za-z_{(]''',",
  "  '''\\{\\{|\\$\\{|%\\(''',",
  "  '''^<[^>]*>$''',",
  "  '''\\w\\(''',",
  "  '''^\\[|\\]$''',",
  "  '''^\\*+$''',",
  "  '''(?i)^(changeme|example|placeholder|redacted|xxx+|your[_-]?\\w*)$''',",
  "  '''(?i)(?:password|passwd|passphrase|pwd|secret|token|пароль|парол|секрет|токен)''',",
  "  '''^[(\\[{]''',",
  "  '''…''',",
  "]",
  "[[rules.allowlists]]",
  "regexTarget = \"match\"",
  "regexes = ['''(?i)secret:[\\w-]+#\\d''']",
  "",
  "[[rules]]",
  "id = \"credentials-pair\"",
  "description = \"A login:password pair after a word about access or credentials, in English or Russian\"",
  "regex = '''(?i)(?:доступ|логин|креды|кред|учётк|учетк|учётн|учетн|аккаунт|вход|access|login|creds|credentials|account|auth)[\\p{L}_-]*(?:[ \\t]+[\\p{L}\\p{N}_.-]{1,20}){0,4}?[ \\t]*[:=—–-]?[ \\t]+[\"'`]?[\\p{L}\\p{N}_.@+-]{2,64}:([^\\s\"'`@]{6,})'''",
  "secretGroup = 1",
  "keywords = [\"доступ\", \"логин\", \"креды\", \"кред\", \"учётк\", \"учетк\", \"учётн\", \"учетн\", \"аккаунт\", \"вход\", \"access\", \"login\", \"creds\", \"credentials\", \"account\", \"auth\"]",
  "[[rules.allowlists]]",
  "regexTarget = \"secret\"",
  "regexes = [",
  "  '''^[\\p{L}_-]+[.,;:!?)]*$''',",
  "  '''^[0-9.,:/_-]+$''',",
  "  '''^[0-9]+[/?#]''',",
  "  '''^//''',",
  "  '''::''',",
  "  '''^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+$''',",
  "  '''[<>]''',",
  "  '''^\\$|\\$\\{|\\{\\{''',",
  "  '''(?i)(?:password|passwd|passphrase|pwd|secret|token|пароль|парол|секрет|токен)''',",
  "]",
  "",
  "[[rules]]",
  "id = \"url-credentials\"",
  "description = \"A password in a URL's user info (scheme://user:password@host)\"",
  "regex = '''\\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\\s:/@\"'`]+:([^\\s:/@\"'`]{3,})@[^\\s/@\"'`]+'''",
  "secretGroup = 1",
  "keywords = [\"://\"]",
  "[[rules.allowlists]]",
  "regexTarget = \"secret\"",
  "regexes = ['''^\\$''', '''^\\{''', '''^<''', '''^\\*+$''', '''(?i)^(password|pass|secret|changeme|xxx+)$''']",
  "",
  "[[rules]]",
  "id = \"bearer-token\"",
  "description = \"A bearer token in an Authorization header\"",
  "regex = '''(?i)\\bbearer[ \\t]+([a-z0-9._~+/-]{16,}=*)'''",
  "secretGroup = 1",
  "entropy = 3.0",
  "keywords = [\"bearer\"]",
  "",
  "[[rules]]",
  "id = \"openai-project-key\"",
  "description = \"An OpenAI project, service-account or admin key\"",
  "regex = '''\\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,})'''",
  "secretGroup = 1",
  "keywords = [\"sk-proj-\", \"sk-svcacct-\", \"sk-admin-\"]",
].join('\n')

/** A long random-looking token with no known shape, by its Shannon entropy. */
export const ENTROPY_RULE = [
  "[[rules]]",
  "id = \"high-entropy-token\"",
  "description = \"A long random-looking token with no known shape\"",
  "regex = '''(?:^|[\\s\"'`=:(,\\[{])([A-Za-z0-9_+/~.-]{20,128}={0,2})(?:$|[\\s\"'`;,)\\]}&])'''",
  "secretGroup = 1",
  "entropy = 4.0",
  "[[rules.allowlists]]",
  "regexTarget = \"secret\"",
  "regexes = [",
  "  '''^[^A-Z]*$''',",
  "  '''^[^a-z]*$''',",
  "  '''^[^0-9]*$''',",
  "  '''\\.''',",
  "  '''^[0-9a-fA-F._-]+$''',",
  "  '''^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-''',",
  "  '''(?i)^(sha1|sha256|sha384|sha512|md5)[-:]''',",
  "  '''^/*[\\w.-]*(/[\\w.@+-]+){2,}/?$''',",
  "  '''^//''',",
  "  '''ABCDEFGHIJ|abcdefghij|0123456789''',",
  "  '''^[\\w-]+(\\.[\\w-]+){2,}$''',",
  "  '''(?i)^(https?|file|git|ssh)[:/]''',",
  "]",
].join('\n')

export type RuleSet = { keywords: boolean; entropy: boolean }

/**
 * The gitleaks configuration the guard runs with: the chosen rules over the
 * project's own `.gitleaks.toml` (which may itself extend the default set),
 * over gitleaks' default set otherwise.
 */
export function configWith(base: string | undefined, rules: RuleSet): string {
  const extend = base === undefined ? 'useDefault = true' : `path = '${base.replace(/'/g, '')}'`
  const chosen = [rules.keywords ? KEYWORD_RULES : '', rules.entropy ? ENTROPY_RULE : ''].filter(Boolean)

  return `[extend]\n${extend}\n\n${chosen.join('\n\n')}\n`
}
