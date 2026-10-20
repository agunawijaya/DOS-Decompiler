"""
paging.py -- One page of an envelope, whatever the target.

A tool result is read by an agent whose context is the cost. A list of 2,000
functions, or the evidence behind a large program's coverage, would spend that
context on one answer. So every list in an envelope that can grow with the
target is cut to `limit` items, with a cursor for the next page, and the page
as a whole is held under MAX_BYTES of JSON: when `limit` items are still too
many bytes, fewer are returned, and the page says so.

The cursor is opaque to the agent: it records where each list's next page
starts, for this tool's lists, and is passed back unchanged.
"""

import base64
import json

DEFAULT_LIMIT = 50
MAX_LIMIT = 500
MAX_BYTES = 64_000


def encode(offsets):
    return base64.urlsafe_b64encode(json.dumps(offsets, sort_keys=True).encode()).decode()


def decode(cursor):
    if not cursor:
        return {}
    try:
        value = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
        if isinstance(value, dict) and all(isinstance(v, int) and v >= 0 for v in value.values()):
            return value
    except (ValueError, UnicodeDecodeError):
        pass
    from safety import Refused
    raise Refused(f"cursor {cursor!r} is not one this server gave",
                  "pass the next_cursor from the previous page unchanged, or none for "
                  "the first page")


def get(env, path):
    node = env
    for key in path[:-1]:
        node = node.get(key) if isinstance(node, dict) else None
        if node is None:
            return None, None
    return node, path[-1]


def page(env, lists, limit=None, cursor=None):
    """Cut each list in `lists` (paths into the envelope, like
    ("result", "functions")) to one page, in place, and add `page`.

    Returns the envelope."""
    from safety import Refused
    limit = DEFAULT_LIMIT if limit is None else limit
    if not isinstance(limit, int) or limit < 1 or limit > MAX_LIMIT:
        raise Refused(f"limit {limit!r} is not between 1 and {MAX_LIMIT}",
                      f"pass a limit from 1 to {MAX_LIMIT}, or none for {DEFAULT_LIMIT}")
    offsets = decode(cursor)
    whole = {}
    for path in lists:
        parent, key = get(env, path)
        if parent is not None and isinstance(parent.get(key), list):
            whole[".".join(path)] = (parent, key, parent[key])

    def cut(n):
        # The next cursor carries every list's position, so a list that has
        # run out stays empty on later pages instead of starting again.
        info, after, more = {}, {}, False
        for name, (parent, key, items) in whole.items():
            start = offsets.get(name, 0)
            parent[key] = items[start:start + n]
            info[name] = {"total": len(items), "offset": start, "returned": len(parent[key])}
            after[name] = min(start + n, len(items))
            more = more or start + n < len(items)
        env["page"] = {"limit": n, "lists": info,
                       "next_cursor": encode(after) if more else None}

    n = limit
    while True:
        cut(n)
        size = len(json.dumps(env))
        if size <= MAX_BYTES or n == 1:
            break
        n = max(1, n // 2)
    if n < limit:
        env["page"]["note"] = (f"{limit} items made the page larger than {MAX_BYTES:,} bytes, "
                               f"so it holds {n}; the cursor continues from there")
    if len(json.dumps(env)) > MAX_BYTES:
        raise Refused(f"one item of this result is larger than the {MAX_BYTES:,}-byte page",
                      "narrow the request: a smaller range, one function, fewer bytes")
    return env
