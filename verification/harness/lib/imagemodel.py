"""Independent model of LaminaDB portable images (checkpoint.lmi / backups).

Written from README.md and PROJECT_SPEC.md, not from the Go code. It exists so
the harness can decide what a correct database *should* expose without asking
laminad's own recovery path. It is also used to craft damaged inputs whose
digests are internally consistent, which forces LaminaDB through its semantic
validation instead of its digest check alone.

Envelope: {"format":1,"sha256":"<hex of payload bytes>","payload":<raw JSON>}
Image payload: {"format":1,"sequence":N,"horizon":H,"catalog":...,
                "store":{"tables":{rel:{key:[version,...]}}}}
"""
import hashlib
import json

MAX_IMAGE = 128 << 20


class ImageError(Exception):
    pass


def decode_envelope(data):
    """Return (envelope_dict, payload_bytes). Raises ImageError."""
    if len(data) > MAX_IMAGE:
        raise ImageError("image exceeds limit")
    try:
        env = json.loads(data)
    except Exception as exc:
        raise ImageError(f"envelope json: {exc}")
    if not isinstance(env, dict):
        raise ImageError("envelope is not an object")
    payload = env.get("payload")
    if not isinstance(payload, dict):
        raise ImageError("payload missing or not an object")
    # Recover the exact bytes Go's json.RawMessage would have captured: the
    # compact/pretty form is irrelevant, but whitespace *inside* the payload is
    # part of the digest. Slice the original text between the payload key and
    # its matching closing brace.
    text = data.decode("utf-8")
    start = text.find('"payload"')
    if start < 0:
        raise ImageError("payload key missing")
    colon = text.find(":", start + 9)
    i = colon + 1
    while i < len(text) and text[i] in " \t\r\n":
        i += 1
    _, end = json.JSONDecoder().raw_decode(text[i:])
    raw = text[i:i + end].encode("utf-8")
    if env.get("format") != 1:
        raise ImageError("image format mismatch")
    if env.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ImageError("image format or digest mismatch")
    return env, raw


def decode(data):
    env, raw = decode_envelope(data)
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise ImageError(f"payload json: {exc}")
    validate(payload)
    return payload


def read(path):
    with open(path, "rb") as fh:
        return decode(fh.read())


def encode(payload):
    """Canonical-enough encoder: digest over the exact payload bytes."""
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return (b'{"format":1,"sha256":"' + hashlib.sha256(raw).hexdigest().encode() +
            b'","payload":' + raw + b"}")


def encode_with_digest(payload, digest):
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return (b'{"format":1,"sha256":"' + digest.encode() + b'","payload":' +
            raw + b"}")


def key_of(value):
    """Primary-key encoding: kind ":" json scalar (datum.Value.Key())."""
    if value is None:
        return "null:null"
    if isinstance(value, bool):
        return "bool:" + ("true" if value else "false")
    if isinstance(value, int):
        return "int:" + str(value)
    if isinstance(value, str):
        return "text:" + json.dumps(value, ensure_ascii=False)
    raise ImageError(f"unsupported scalar {value!r}")


def normalize(relation, row):
    if not isinstance(row, dict):
        raise ImageError("row is not an object")
    columns = {c["name"]: c for c in relation["columns"]}
    for name in row:
        if name not in columns:
            raise ImageError(f"unknown column {name!r}")
    out = {}
    for name, col in columns.items():
        value = row.get(name)
        if value is None:
            if not col.get("nullable"):
                raise ImageError(f"column {name} cannot be null")
            out[name] = None
            continue
        kind = "bool" if isinstance(value, bool) else (
            "int" if isinstance(value, int) else "text" if isinstance(value, str) else None)
        if kind != col["type"]:
            raise ImageError(f"column {name} requires {col['type']}")
        if kind == "text" and len(value) > 65536:
            raise ImageError("text exceeds 64KiB")
        out[name] = value
    return out


def relation_map(image):
    return {r["name"]: r for r in image["catalog"]["relations"].values()} \
        if isinstance(image["catalog"].get("relations"), dict) else {}


def validate(image):
    if not isinstance(image, dict):
        raise ImageError("image is not an object")
    if image.get("format") != 1:
        raise ImageError("invalid image header")
    seq = image.get("sequence")
    horizon = image.get("horizon")
    if not isinstance(seq, int) or not isinstance(horizon, int) or horizon > seq:
        raise ImageError("invalid image header")
    catalog = image.get("catalog")
    store = image.get("store")
    if not isinstance(catalog, dict) or not isinstance(store, dict):
        raise ImageError("invalid image header")
    if not isinstance(catalog.get("relations"), dict) or \
       not isinstance(catalog.get("indexes"), dict) or \
       not isinstance(store.get("tables"), dict):
        raise ImageError("invalid image header")
    for name, rel in catalog["relations"].items():
        if name != rel.get("name") or not isinstance(rel.get("created"), int) or \
           rel["created"] == 0 or rel["created"] > seq:
            raise ImageError("invalid catalog sequence")
        if not rel.get("columns"):
            raise ImageError("relation needs 1..64 columns")
        columns = {c["name"]: c for c in rel["columns"]}
        if rel.get("primary") not in columns:
            raise ImageError("primary column does not exist")
        if columns[rel["primary"]]["nullable"] or \
           columns[rel["primary"]]["type"] == "bool":
            raise ImageError("primary must be non-null int or text")
    for name, idx in catalog["indexes"].items():
        rel = catalog["relations"].get(idx.get("relation"))
        if rel is None or name != idx.get("name") or \
           not isinstance(idx.get("created"), int) or \
           idx["created"] < rel["created"] or idx["created"] > seq:
            raise ImageError("invalid index metadata")
        if not any(c["name"] == idx.get("column") for c in rel["columns"]):
            raise ImageError("invalid index column")
    for name, rows in store["tables"].items():
        rel = catalog["relations"].get(name)
        if rel is None:
            raise ImageError("image references unknown relation")
        for key, chain in rows.items():
            if not chain:
                raise ImageError("empty version chain")
            last = 0
            for v in chain:
                if v["sequence"] <= last or v["sequence"] > seq or \
                   v["sequence"] <= rel["created"]:
                    raise ImageError("invalid version order")
                last = v["sequence"]
                if not v.get("deleted"):
                    row = normalize(rel, v.get("row") or {})
                    if key_of(row[rel["primary"]]) != key:
                        raise ImageError("invalid stored tuple")
    for idx in catalog["indexes"].values():
        if not idx.get("unique"):
            continue
        seen = set()
        for chain in store["tables"].get(idx["relation"], {}).values():
            version = visible(chain, seq)
            if version is None or version.get("deleted"):
                continue
            value = (version.get("row") or {}).get(idx["column"])
            if value is None:
                continue
            k = key_of(value)
            if k in seen:
                raise ImageError("image violates unique index")
            seen.add(k)


def visible(chain, at):
    """Last version with sequence <= at (may be a tombstone)."""
    lo, hi = 0, len(chain)
    while lo < hi:
        mid = (lo + hi) // 2
        if chain[mid]["sequence"] <= at:
            lo = mid + 1
        else:
            hi = mid
    if lo == 0:
        return None
    return chain[lo - 1]


def visible_rows(image, relation, at):
    rows = {}
    for key, chain in image["store"]["tables"].get(relation, {}).items():
        v = visible(chain, at)
        if v is None or v.get("deleted"):
            continue
        rows[key] = dict(v["row"])
    return rows
