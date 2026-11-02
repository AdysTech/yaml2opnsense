"""Plan mode: record mutations against live config and render a delta report.

The existing `apply_*` modules already compute desired-vs-live and only mutate
through `client.post(...)`; reads go through `client.get(...)` (plus a few
POST-shaped search endpoints). Plan mode therefore runs them unchanged against
a RecordingClient: reads pass through and cache live rows, writes are
classified and recorded as PlanActions — never sent to OPNsense.
"""
import re
from dataclasses import dataclass

_WRITE_RE = re.compile(r"^(add|set|delete|del|update|create|insert)([_\-]?(.+))?$")
# OPNsense returns dashed uuids (8-4-4-4-12) in some APIs and bare 32-hex in others.
_UUID_RE = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$|^[0-9a-f]{32}$")
_UUID_TAIL_RE = re.compile(
    r"/([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|[0-9a-f]{32})/?$")
_SECRET_RE = re.compile(r"secret|password", re.I)
_SECTION_FOR_ITEM = {"vlan_settings": "vlan", "alias": "alias", "filter": "rule"}
_MODULE_LABELS = {
    "interfaces": "Interfaces / VLANs",
    "dnsmasq": "DHCP (dnsmasq)",
    "unbound": "DNS (Unbound)",
    "freeradius": "FreeRADIUS",
    "haproxy": "HAProxy",
    "firewall": "Firewall (aliases)",
}
_IDENTIFY = ("name", "host", "hostname", "domain", "interface", "address", "port",
             "option", "value", "hwaddr", "ip", "server", "start_addr", "end_addr",
             "username", "descr", "description")


@dataclass
class PlanAction:
    module: str
    resource: str
    op: str  # create | update | delete | commit
    name: str = ""
    changes: list | None = None  # [(field, old, new), ...] for updates
    commit: str = ""  # "reconfigure" | "configtest"


class RecordingClient:
    def __init__(self, inner):
        self._inner = inner
        self.actions = []
        self._rows = {}
        self._added_tags = []
        self._synth = 0

    # -- reads: pass through, cache rows -------------------------------
    def get(self, path):
        data = self._inner.get(path)
        if path == "/api/dnsmasq/settings/get_tag_list" and self._added_tags:
            return self._merge_added_tags(data)
        if isinstance(data, dict):
            self._cache_node(data)
            self._cache_by_path_uuid(path, data)
        return data

    # -- writes: classify and record, never send -----------------------
    def post(self, path, payload=None):
        clean = path.rstrip("/")
        segs = [s for s in clean.split("/") if s]
        module = segs[1] if len(segs) > 1 else "?"
        last = segs[-1].lower()

        if last in ("reconfigure", "configtest"):
            self.actions.append(PlanAction(module, "", "commit", commit=last))
            return {"result": ""} if last == "configtest" else {}

        if last.startswith("search"):
            data = self._inner.post(path, payload)
            if isinstance(data, dict):
                self._cache_node(data)
            return data

        # uuid-suffixed endpoints carry the verb one segment earlier:
        # .../set_host/{uuid}, .../delServer/{uuid}; add endpoints have no uuid.
        uuid = last if _UUID_RE.match(last) and len(segs) >= 4 else None
        verb_seg = segs[-2].lower() if uuid else last
        m = _WRITE_RE.match(verb_seg)
        if not m:
            raise RuntimeError(f"plan mode: unknown write endpoint {path}")
        verb = m.group(1)
        rest = m.group(3) or ""
        op = {"add": "create", "create": "create", "insert": "create",
              "set": "update", "update": "update",
              "delete": "delete", "del": "delete"}[verb]
        resource = rest.lower().replace("_", " ") or "item"
        if resource == "item" and len(segs) >= 3:
            resource = _SECTION_FOR_ITEM.get(segs[2], resource)
        record = _unwrap(payload)

        if verb_seg == "add_tag":
            self._added_tags.append(str(record.get("name", "")))

        if op == "create":
            self.actions.append(PlanAction(module, resource, "create",
                                           name=_identify(record)))
            self._synth += 1
            return {"uuid": f"plan-{self._synth}"}  # haproxy sync consumes result["uuid"]

        if op == "update":
            cached = self._rows.get(uuid)
            self.actions.append(PlanAction(module, resource, "update",
                name=_identify(record) or uuid[:8],
                changes=_diff(cached, record) if cached else None))
            return {}

        # delete (haproxy del* — payload is None)
        cached = self._rows.get(uuid)
        self.actions.append(PlanAction(module, resource, "delete",
            name=_identify_cached(cached) if cached else uuid))
        return {}

    # -- caching --------------------------------------------------------
    def _cache_node(self, node):
        """Recursively cache any row dict carrying a str uuid, and id-maps."""
        if isinstance(node, list):
            for item in node:
                self._cache_node(item)
            return
        if not isinstance(node, dict):
            return
        if isinstance(node.get("uuid"), str):
            self._rows[node["uuid"]] = node
            return
        if node and all(isinstance(v, dict) and _UUID_RE.match(str(k)) for k, v in node.items()):
            # freeradius shape: {uuid: row, ...}
            for k, v in node.items():
                self._rows[k] = {"uuid": k, **v}
            return
        for value in node.values():
            self._cache_node(value)

    def _cache_by_path_uuid(self, path, data):
        """get_*/{uuid} responses whose inner row lacks its own uuid."""
        m = _UUID_TAIL_RE.search(path)
        if not m or not isinstance(data, dict) or len(data) != 1:
            return
        inner = next(iter(data.values()))
        if isinstance(inner, dict) and "uuid" not in inner:
            self._rows[m.group(1)] = {"uuid": m.group(1), **inner}

    def _merge_added_tags(self, data):
        """Fidelity fix: tags created this run must look present to later reads."""
        if not isinstance(data, dict):
            return data
        items = list((data.get("tags") or {}).get("items") or [])
        labels = {i.get("label") for i in items if isinstance(i, dict)}
        for name in self._added_tags:
            if name not in labels:
                items.append({"label": name, "value": f"plan-new:{name}"})
                labels.add(name)
        return {**data, "tags": {"items": items}}


def _unwrap(payload):
    """Strip a single-key wrapper ({"host": {...}}); unbound payloads are raw."""
    if isinstance(payload, dict) and len(payload) == 1:
        value = next(iter(payload.values()))
        if isinstance(value, dict):
            return value
    return payload if isinstance(payload, dict) else {}


def _fmt(value):
    return "<unset>" if value is None else str(value)


def _diff(cached, record):
    changes = []
    for key, new in record.items():
        if key == "uuid":
            continue
        old = cached.get(key)
        if _fmt(old) != _fmt(new):
            changes.append((key, old, new))
    return changes


def _identify(record):
    if not isinstance(record, dict):
        return ""
    parts = [str(record[k]) for k in _IDENTIFY
             if record.get(k) not in (None, "") and not isinstance(record.get(k), (dict, list))]
    return ", ".join(parts[:2])


def _identify_cached(cached):
    """Identify a cached row; search rows may be wrapped ({"server": {...}})."""
    name = _identify(cached)
    if name or not isinstance(cached, dict):
        return name
    for value in cached.values():
        name = _identify(value)
        if name:
            return name
    return ""


def _mutation_label(action):
    """The symbol used in the delta for each mutation kind."""
    return {"create": "+", "update": "~", "delete": "-"}[action.op]


def render_plan(actions):
    """Render the recorded PlanActions as a terraform-style delta report."""
    if not has_mutations(actions):
        return "No changes.\nThe live configuration already matches the YAML."

    lines = []
    current_module = None
    i = 0
    while i < len(actions):
        action = actions[i]
        if action.module != current_module:
            current_module = action.module
            lines.append("")
            lines.append(f"  {_MODULE_LABELS.get(current_module, current_module)}")
        if action.op == "commit":
            # Merge consecutive same-module commit actions into one line.
            commits = []
            while i < len(actions) and actions[i].op == "commit" \
                    and actions[i].module == current_module:
                commits.append(actions[i].commit)
                i += 1
            if "configtest" in commits and "reconfigure" in commits:
                lines.append("    » configtest + reconfigure")
            else:
                lines.append(f"    » {', '.join(sorted(set(commits)))}")
            continue
        label = f": {action.name}" if action.name else ""
        lines.append(f"    {_mutation_label(action)} {action.op} {action.resource}{label}")
        if action.op == "update" and action.changes is not None:
            shown = 0
            for field, old, new in action.changes:
                if shown >= 5:
                    break
                if _SECRET_RE.search(field):
                    lines.append(f"        {field}: <changed>")
                else:
                    lines.append(f"        {field}: {_fmt(old)} → {_fmt(new)}")
                shown += 1
            if len(action.changes) > 5:
                lines.append(f"        … +{len(action.changes) - 5} more field(s) changed")
        i += 1

    adds = sum(1 for a in actions if a.op == "create")
    changes = sum(1 for a in actions if a.op == "update")
    destroys = sum(1 for a in actions if a.op == "delete")
    parts = []
    if adds:
        parts.append(f"{adds} to add")
    if changes:
        parts.append(f"{changes} to change")
    if destroys:
        parts.append(f"{destroys} to destroy")
    lines.append("")
    lines.append(f"Plan: {', '.join(parts)}")
    return "\n".join(lines)


def has_mutations(actions):
    """True if any action would actually change the live box."""
    return any(a.op in ("create", "update", "delete") for a in actions)
