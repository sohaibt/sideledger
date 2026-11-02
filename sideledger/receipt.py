"""Turn stored rows into a receipt: text for people, JSON and SARIF for tools."""
import json
import time

from . import __version__

LIMITS = ("sideledger reads command text only. A side effect hidden inside a script is rated unknown at best, "
          "and nothing here proves a command did only what its text says.")
LEVELS = dict(irreversible="error", unknown="warning", reversible="note")
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
HOMEPAGE = "https://github.com/sohaibt/sideledger"


def build(rows, session, turn, show_all=False):
    shown = [r for r in rows if show_all or r["categories"] != "local" or r["rating"] != "reversible"]
    actions = [dict(
        id=r["id"],
        time=time.strftime("%Y-%m-%d %H:%M", time.localtime(r["ts"])),
        turn=r["turn"],
        cwd=r["cwd"],
        command=r["command"],
        categories=r["categories"].split(","),
        rating=r["rating"],
        rule=r["rule"],
        why=r["why"],
        destinations=r["destinations"].split(", ") if r["destinations"] else [],
        failed=bool(r["failed"]),
        reviewed=r["acked_at"] is not None,
    ) for r in shown]
    return dict(session=session, turn=turn, total=len(rows), local_hidden=len(rows) - len(shown), actions=actions, limits=LIMITS)


def action_lines(action):
    tags = []
    if action["failed"]:
        tags.append("failed, may have partly run")
    if action["reviewed"]:
        tags.append("reviewed")
    head = "  #%d %s  %s  %s" % (action["id"], action["time"], ",".join(action["categories"]), action["command"])
    lines = [head, "      why: " + action["why"]]
    if action["destinations"]:
        lines.append("      to:  " + ", ".join(action["destinations"]))
    if tags:
        lines.append("      note: " + "; ".join(tags))
    return lines


def to_text(data):
    where = "turn %d" % data["turn"] if data["turn"] is not None else "all turns"
    lines = ["sideledger receipt: session %s, %s" % (data["session"], where), ""]
    if not data["actions"]:
        lines += ["Nothing outside the repo, as far as the command text shows.", ""]
    for rating in ("irreversible", "unknown", "reversible"):
        group = [a for a in data["actions"] if a["rating"] == rating]
        if group:
            lines.append("%s (%d)" % (rating.upper(), len(group)))
            for action in group:
                lines += action_lines(action)
            lines.append("")
    if data["local_hidden"]:
        noun = "command" if data["local_hidden"] == 1 else "commands"
        lines += ["%d local %s hidden (--all shows them)." % (data["local_hidden"], noun), ""]
    lines.append("Limits: " + data["limits"])
    return "\n".join(lines)


def to_json(data):
    return json.dumps(data, indent=2)


def to_sarif(data):
    rule_ids, rules, results = [], [], []
    for action in data["actions"]:
        if action["rule"] not in rule_ids:
            rule_ids.append(action["rule"])
            rules.append(dict(id=action["rule"], shortDescription=dict(text=action["why"])))
        result = dict(
            ruleId=action["rule"],
            ruleIndex=rule_ids.index(action["rule"]),
            level=LEVELS[action["rating"]],
            message=dict(text=action["command"] + ": " + action["why"]),
            locations=[dict(logicalLocations=[dict(fullyQualifiedName="%s/turn-%d" % (data["session"], action["turn"]), kind="module")])],
            properties=dict(rating=action["rating"], categories=action["categories"], destinations=action["destinations"],
                            failed=action["failed"], time=action["time"], cwd=action["cwd"]),
        )
        if action["reviewed"]:
            result["suppressions"] = [dict(kind="external")]
        results.append(result)
    driver = dict(name="sideledger", version=__version__, informationUri=HOMEPAGE, rules=rules)
    run = dict(tool=dict(driver=driver), results=results, properties=dict(limits=data["limits"]))
    doc = dict(version="2.1.0", runs=[run])
    doc["\x24schema"] = SARIF_SCHEMA
    return json.dumps(doc, indent=2)


FORMATS = dict(text=to_text, json=to_json, sarif=to_sarif)
