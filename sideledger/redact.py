"""Remove secrets and payload bodies from command text before it is stored."""
import re

MASK = "[REDACTED]"
BODY = "[body-removed]"
MAX_LEN = 2000

VALUE = r"""(?:(?:"(?:[^"\\]|\\.)*"|'[^']*'|[^\s'"])+|['"][^\n]*)"""
WORD = r"(?:secret|token|pass(?:w(?:or)?d|phrase)?|pwd|pw(?![a-z])|api[_-]?key|[_-]key(?![a-z])|auth(?!or)|credential|cookie|signature)"

PRIVATE_KEY = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*-----|\Z)", re.S)
HEREDOC = re.compile(r"(?<!<)<<(-?\s*)(['" r'"' r"]?)([\w.-]+)\2([^\n]*)\n.*?(?:^\s*\3\s*$|\Z)", re.S | re.M)
HERESTRING = re.compile(r"<<<\s*" + VALUE)
PIPED_TEXT = re.compile(r"\b(echo|printf)\s+(?:-\w+\s+)*" + VALUE + r"(\s*\|)")
LONG_BODY_FLAG = re.compile(r"(--(?:data(?:-[\w-]+)?|json|form(?:-string)?|post-data|body(?:-data)?|raw-field|field|notes))(\s+|=)" + VALUE)
SQL_LINE = re.compile(r"\b(?:psql|mysql|mariadb|sqlite3|cockroach|clickhouse-client|wrangler\s+d1\s+execute)\b[^\n]*")
PASS_ATTACHED = re.compile(r"\b(mysql|mariadb|mysqldump)\b([^\n]*?\s)-p(?!\s)\S+")
TOOL_FLAGS = [
    # curl takes bodies attached and in flag clusters (-dX, -sd X). Its -f is --fail, so that one is only a body for gh.
    (re.compile(r"\bcurl\b[^\n]*"), re.compile(r"(\s-[a-zA-Z]*[dF])(\s*)" + VALUE)),
    (re.compile(r"\bgh\b[^\n]*"), re.compile(r"(\s-[fFbn])(\s+)" + VALUE)),
    (re.compile(r"(?:^|[;&|]\s*)(?:https?|xh)\s[^\n]*", re.M), re.compile(r"(\s[\w.-]+)(:?=)" + VALUE)),
    (re.compile(r"\b(?:(?:fly|flyctl|supabase|doppler)\s+secrets\s+set|heroku\s+config:set|railway\s+variables)\b[^\n]*"), re.compile(r"(\s[\w.-]+)(=)" + VALUE)),
    (re.compile(r"\bkubectl\s+create\s+secret\b[^\n]*"), re.compile(r"(--from-literal=[^=\s]+)(=)" + VALUE)),
    (re.compile(r"\baws\s+configure\s+set\b[^\n]*"), re.compile(r"(\s\S*(?:secret|token|key)\S*)(\s+)" + VALUE)),
    (re.compile(r"\b(?:sshpass|docker login|podman login|helm registry login)\b[^\n]*"), re.compile(r"(\s-p)(\s*)" + VALUE)),
    (re.compile(r"\bredis-cli\b[^\n]*"), re.compile(r"(\s-a)(\s+)" + VALUE)),
    (re.compile(r"\bcurl\b[^\n]*"), re.compile(r"(\s(?:-u|--user|-b|--cookie|--oauth2-bearer|-E|--cert))(\s+|=)" + VALUE)),
]
HEADER = re.compile(r"(?i)\b(authorization|proxy-authorization|set-cookie|cookie|x-[\w-]*(?:key|token|secret|auth)[\w-]*|api-?key)\s*:\s*[^'" r'"' r"\n]*")
URL_PASSWORD = re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@'" r'"' r"]+:)[^\s/'" r'"' r"]+@")
WEBHOOK_URL = re.compile(r"""(?i)(\bhttps?://[^\s'"]*hook[^\s/'"]*/)[^\s'"]+""")
URL_TOKEN = re.compile(r"(\bhttps?://)[^/\s:@'" r'"' r"]+@")
QUERY = re.compile(r"(?i)([?&][\w.-]*(?:secret|token|key|sig|signature|pass|pwd|code)[\w.-]*=)[^&\s'" r'"' r"#]+")
FLAG = re.compile(r"(?i)(--?[\w-]*" + WORD + r"[\w-]*)(=|\s+)" + VALUE)
ASSIGN = re.compile(r"(?i)([\w./:-]*" + WORD + r"[\w.-]*[" + r'"' + r"']?\s*[=:]\s*)" + VALUE)
TOKEN_SHAPES = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{10,}|github_pat_\w{10,}|glpat-[\w-]{10,}|sk-[\w-]{10,}|sk_(?:live|test)_\w{8,}"
    r"|rk_(?:live|test)_\w{8,}|(?:AKIA|ASIA)[A-Z0-9]{12,}|xox[abeoprs]-[\w-]{8,}|npm_\w{10,}|pypi-[\w-]{10,}"
    r"|SG\.[\w-]{10,}\.[\w-]{10,}|AIza[\w-]{20,}|bot\d{6,}:[\w-]{20,}|eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*)"
)
LONG_HEX = re.compile(r"\b[a-f0-9]{32,}\b")
LONG_MIXED = re.compile(r"(?<![\w+=-])[A-Za-z0-9_+=-]{32,}(?![\w+=-])")
AWS_SECRET_SHAPE = re.compile(r"(?<![\w+/=-])[A-Za-z0-9/+]{40}(?![\w+/=-])")


def _sql_values(match):
    # Keep the statement, drop the literals, whichever quote style wraps the statement.
    text = re.sub(r'"[^"]*"', lambda q: re.sub(r"'[^']*'", "'" + MASK + "'", q.group(0)), match.group(0))
    text = re.sub(r"'[^']*'", lambda q: re.sub(r'"[^"]*"', '"' + MASK + '"', q.group(0)), text)
    text = re.sub(r"\$\$.*?\$\$", MASK, text)
    text = re.sub(r"(?i)\bVALUES\s*\([^)]*\)", "VALUES (" + MASK + ")", text)
    return re.sub(r"(\s\w+\s*=\s*)-?\d[\d.]*\b", lambda m: m.group(1) + MASK, text)


def _mixed(match):
    text = match.group(0)
    is_secret = re.search(r"[a-z]", text) and re.search(r"[A-Z]", text) and re.search(r"[0-9]", text)
    return MASK if is_secret else text


def _within(line_pattern, flag_pattern, replacement, text):
    return line_pattern.sub(lambda m: flag_pattern.sub(replacement, m.group(0)), text)


def redact(command):
    """Return command text that is safe to store. Over-redacts rather than leaks."""
    text = PRIVATE_KEY.sub(MASK, command)
    text = HEREDOC.sub(lambda m: "<<" + m.group(1) + m.group(2) + m.group(3) + m.group(2) + m.group(4) + "\n" + BODY, text)
    text = HERESTRING.sub("<<< " + BODY, text)
    text = PIPED_TEXT.sub(lambda m: m.group(1) + " " + BODY + m.group(2), text)
    text = LONG_BODY_FLAG.sub(lambda m: m.group(1) + m.group(2) + BODY, text)
    text = SQL_LINE.sub(_sql_values, text)
    text = PASS_ATTACHED.sub(lambda m: m.group(1) + m.group(2) + "-p" + MASK, text)
    for line_pattern, flag_pattern in TOOL_FLAGS:
        text = _within(line_pattern, flag_pattern, lambda m: m.group(1) + m.group(2) + MASK, text)
    text = HEADER.sub(lambda m: m.group(1) + ": " + MASK, text)
    text = URL_PASSWORD.sub(lambda m: m.group(1) + MASK + "@", text)
    text = WEBHOOK_URL.sub(lambda m: m.group(1) + MASK, text)
    text = URL_TOKEN.sub(lambda m: m.group(1) + MASK + "@", text)
    text = QUERY.sub(lambda m: m.group(1) + MASK, text)
    text = FLAG.sub(lambda m: m.group(1) + m.group(2) + MASK, text)
    text = ASSIGN.sub(lambda m: m.group(1) + MASK, text)
    text = TOKEN_SHAPES.sub(MASK, text)
    text = LONG_HEX.sub(MASK, text)
    text = LONG_MIXED.sub(_mixed, text)
    text = AWS_SECRET_SHAPE.sub(_mixed, text)
    return text[:MAX_LEN] + "…" if len(text) > MAX_LEN else text
