"""Rate a shell command from its text alone, using the public ruleset in rules.json.

The command is split into pieces (&&, ;, pipes, subshells, command substitution, bash -c).
Each piece is matched against the rules in order; the first match wins. The worst rating is kept.
"""
import json
import pathlib
import re
import shlex

CATEGORIES = ("git-push", "deploy", "database", "cloud", "package-publish", "network", "local")
RATINGS = ("reversible", "unknown", "irreversible")

RULES = json.loads(pathlib.Path(__file__).with_name("rules.json").read_text())
for _rule in RULES:
    _rule["regex"] = re.compile(_rule["pattern"])

SQ, DQ, DOLLAR, BACKTICK = "\x27", "\x22", "\x24", "\x60"
SUBST = DOLLAR + "\x28"
SHELLS = ("bash", "sh", "zsh", "dash", "ksh")
SKIP = ("fi", "done", "esac", "\x7d", ";;", "for", "case", "select", "function")
KEYWORDS = ("then", "do", "else", "elif", "if", "while", "until", "!", "\x7b")
# Wrapper -> its options that take a value. The wrapped command is what gets rated.
WRAPPERS = dict([
    ("sudo", ["-u", "-g", "-h", "-p", "-C", "-r", "-t", "-U"]), ("doas", ["-u", "-C"]), ("env", ["-u", "-C", "-S"]),
    ("xargs", ["-n", "-I", "-P", "-L", "-s", "-E", "-d", "-J"]), ("nice", ["-n"]), ("npx", ["-p", "--package", "-c"]),
    ("timeout", ["-s", "-k"]), ("bunx", []), ("time", []), ("nohup", []), ("command", []), ("exec", []),
    ("builtin", []), ("caffeinate", []), ("setsid", []),
])
PREFIXES = (("pnpm", "dlx"), ("pnpm", "exec"), ("yarn", "dlx"), ("npm", "exec"), ("bundle", "exec"),
            ("uv", "run"), ("poetry", "run"), ("pdm", "run"), ("pipx", "run"), ("rye", "run"))
HEREDOC = re.compile(r"(?<!<)<<-?\s*([\x27\x22]?)([\w.-]+)\1([^\n]*)\n(.*?)(?:^\s*\2\s*$|\Z)", re.S | re.M)

URL = re.compile(r"(?:^|=)([a-zA-Z][a-zA-Z0-9+.-]*)://(?:[^/@\s]*@)?([^/\s?#\x27\x22]+)")
SCP = re.compile(r"^(?:[\w.-]+@)?([\w.-]+):(?!//)")
BARE_HOST = re.compile(r"^[\w-]+(?:\.[\w-]+)+(?::\d+)?(?:/\S*)?$")
VARIABLE = re.compile(r"^\x24\x7b?(\w+)\x7d?")
BODY_PREFIXES = ("--data", "--json", "--form", "--post", "--body", "--header", "--output")
HTTP_VALUE_FLAGS = ("-o", "-H", "-d", "-X", "-u", "-A", "-e", "-b", "-c", "-F", "-T", "-m", "-w", "-x", "-O", "-E",
                    "--request", "--user", "--user-agent", "--referer", "--cookie", "--upload-file", "--max-time",
                    "--write-out", "--proxy", "--connect-timeout", "--retry")
SSH_VALUE_FLAGS = ("-i", "-p", "-l", "-o", "-F", "-J", "-b", "-c", "-D", "-E", "-L", "-R", "-S", "-W", "-w", "-e", "-m", "-Q")
DB_CLIENTS = ("psql", "mysql", "mariadb", "redis-cli", "pg_dump", "pg_restore", "mysqldump", "mongosh", "mongo", "clickhouse-client")


def _attach_heredocs(text):
    # Move each heredoc body into one quoted word on its own command, so its lines are not read as commands.
    def inline(m):
        return "<<" + SQ + m.group(4).replace(SQ, "") + SQ + m.group(3) + "\n"
    return HEREDOC.sub(inline, text)


def _closing(text, start):
    depth = 1
    for i in range(start, len(text)):
        if text[i] == "\x28":
            depth += 1
        elif text[i] == "\x29":
            depth -= 1
            if not depth:
                return i
    return len(text)


def _split(text):
    """Split on shell separators outside quotes. Returns (pieces, command substitutions)."""
    pieces, subs, buf, quote, i, n = [], [], [], None, 0, len(text)

    def flush():
        if "".join(buf).strip():
            pieces.append("".join(buf))
        buf.clear()

    while i < n:
        c = text[i]
        if c == "\\" and quote != SQ:
            if text[i + 1:i + 2] != "\n":
                buf.append(text[i:i + 2])
            i += 2
        elif quote == SQ:
            quote = None if c == SQ else quote
            buf.append(c)
            i += 1
        elif text.startswith(SUBST + "\x28", i):  # arithmetic, not a command
            end = text.find("\x29\x29", i)
            end = n if end < 0 else end + 2
            buf.append("0")
            i = end
        elif text.startswith(SUBST, i):
            end = _closing(text, i + 2)
            subs.append(text[i + 2:end])
            buf.append("SUBSTITUTED")
            i = end + 1
        elif c == BACKTICK:
            end = text.find(BACKTICK, i + 1)
            end = n if end < 0 else end
            subs.append(text[i + 1:end])
            buf.append("SUBSTITUTED")
            i = end + 1
        elif quote == DQ:
            quote = None if c == DQ else quote
            buf.append(c)
            i += 1
        elif c in (SQ, DQ):
            quote = c
            buf.append(c)
            i += 1
        elif c == "#" and (not buf or buf[-1].isspace()):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith(("&&", "||", ";;"), i):
            flush()
            i += 2
        elif c == "&" and (text[i - 1:i] == ">" or text[i + 1:i + 2] == ">"):  # 2>&1, &>file
            buf.append(c)
            i += 1
        elif c in ";|&\n\x28\x29":
            flush()
            i += 1
        else:
            buf.append(c)
            i += 1
    flush()
    return pieces, subs


def _tokens(piece):
    try:
        return shlex.split(piece)
    except ValueError:
        return piece.split()


def _unwrap(tokens):
    """Drop env assignments, sudo-style wrappers and shell keywords, so the real command comes first."""
    while tokens:
        first = tokens[0]
        if first in KEYWORDS or re.match(r"^\w+=", first):
            tokens = tokens[1:]
        elif first in WRAPPERS:
            value_flags, is_timeout, rest, i = WRAPPERS[first], first == "timeout", tokens[1:], 0
            while i < len(rest) and (rest[i].startswith("-") or re.match(r"^\w+=", rest[i])):
                i += 2 if rest[i] in value_flags else 1
            tokens = rest[i + 1 if is_timeout else i:]
        elif tuple(tokens[:2]) in PREFIXES:
            tokens = tokens[2:]
        elif re.match(r"^python[\d.]*$", first) and tokens[1:2] == ["-m"]:
            tokens = tokens[2:]
        else:
            if "/" in first and (not first.startswith(".") or "/.bin/" in first):
                tokens = [first.rsplit("/", 1)[1]] + tokens[1:]
            return tokens
    return []


def _commands(text):
    """Yield the token list of every command the text would run, as far as the text shows."""
    pieces, subs = _split(_attach_heredocs(text))
    for sub in subs:
        yield from _commands(sub)
    for piece in pieces:
        tokens = _unwrap(_tokens(piece))
        if not tokens or tokens[0] in SKIP:
            continue
        if tokens[0] == "eval":
            yield from _commands(" ".join(tokens[1:]))
            continue
        if tokens[0] == "find":
            # find -exec runs another command, and that command is the one that counts.
            yield from _find_exec(tokens)
        if tokens[0] in SHELLS:
            inner = _shell_body(tokens)
            if inner is not None:
                yield from _commands(inner)
                continue
        yield tokens


def _find_exec(tokens):
    for i, token in enumerate(tokens):
        if token in ("-exec", "-execdir", "-ok", "-okdir"):
            inner = []
            for word in tokens[i + 1:]:
                if word in (";", "+"):
                    break
                inner.append(word)
            yield from _commands(shlex.join(inner))


def _shell_body(tokens):
    for i, token in enumerate(tokens[1:], 1):
        if re.match(r"^-[a-z]*c$", token) and i + 1 < len(tokens):
            return tokens[i + 1]
        if token.startswith("<<") and not token.startswith("<<<"):
            return token[2:]
    return None


def _match(tokens):
    text = re.sub(r"\s+", " ", " ".join(tokens)).strip()
    return next(rule for rule in RULES if rule["regex"].search(text))


def destinations_of(tokens):
    """Hosts named by one command. Never includes passwords, paths, queries or body values."""
    tool, args, found = tokens[0], tokens[1:], []

    if tool == "git":
        positional = [t for t in args[args.index("push") + 1:] if not t.startswith(("-", "+"))] if "push" in args else []
        if not positional:
            return []
        url, scp = URL.search(positional[0]), SCP.match(positional[0])
        if url:
            return [url.group(1) + "://" + url.group(2)]
        return [scp.group(1)] if scp else [positional[0]]

    if tool == "ssh":
        i = 0
        while i < len(args):
            if args[i] in SSH_VALUE_FLAGS:
                i += 2
            elif args[i].startswith("-"):
                i += 1
            else:
                return [args[i].rsplit("@", 1)[-1]]
        return []

    if tool in ("scp", "rsync", "sftp"):
        return [m.group(1) for m in (SCP.match(t) for t in args if not t.startswith("-")) if m]

    skip, is_http = False, tool in ("curl", "wget")
    for i, token in enumerate(args):
        if skip:
            skip = False
        elif token.startswith(BODY_PREFIXES):
            skip = "=" not in token and is_http
        elif is_http and token in HTTP_VALUE_FLAGS:
            skip = True
        elif tool in DB_CLIENTS and token in ("-h", "--host") and i + 1 < len(args):
            found.append(args[i + 1])
            skip = True
        elif tool in DB_CLIENTS and token.startswith("--host="):
            found.append(token.split("=", 1)[1])
        elif URL.search(token):
            m = URL.search(token)
            found.append(m.group(1) + "://" + m.group(2))
        elif (is_http or tool in DB_CLIENTS) and VARIABLE.match(token):
            found.append(DOLLAR + VARIABLE.match(token).group(1))
        elif is_http and not token.startswith("-") and BARE_HOST.match(token):
            found.append(token.split("/", 1)[0])
    return found


def classify(command):
    """Return dict(categories, rating, rule, why, destinations) for a command's text."""
    worst, categories, destinations = None, [], []
    for tokens in _commands(command):
        rule = _match(tokens)
        rank = (RATINGS.index(rule["rating"]), rule["category"] != "local")
        if worst is None or rank > (RATINGS.index(worst["rating"]), worst["category"] != "local"):
            worst = rule
        if rule["category"] != "local":
            if rule["category"] not in categories:
                categories.append(rule["category"])
            destinations += [d for d in destinations_of(tokens) if d not in destinations]
    if worst is None:
        return dict(categories=["local"], rating="reversible", rule="empty", why="Nothing to run.", destinations=[])
    return dict(categories=categories or ["local"], rating=worst["rating"], rule=worst["id"], why=worst["why"], destinations=destinations)
