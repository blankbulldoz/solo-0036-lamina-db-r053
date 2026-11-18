"""Independent journal parser for LaminaDB's LMW1 journal.

This is a *model*, deliberately written from the README's documented format
rather than by calling into laminad. It answers the questions the harness must
answer without borrowing the database's recovery result:

  * which frames are intact (length + CRC32 + sequence continuity),
  * how many trailing bytes are an incomplete tail,
  * which commit records are present in the byte image,
  * which sequence numbers a correct instance must expose after recovery.

Frame layout, as documented in README.md:
    header:  16 bytes  "LMW1" | uint64 BE base | uint32 BE crc32(header[:12])
    frame:   uint32 BE payload length | uint32 BE crc32(payload) | payload
    payload: JSON journal record (format 1, sequence base+1, base+2, ...)
"""
import json
import struct
import zlib

HEADER = 16
MAX_FRAME = 16 << 20


class Frame:
    __slots__ = ("offset", "length", "stored_crc", "payload", "crc_ok", "record")

    def __init__(self, offset, length, stored_crc, payload):
        self.offset = offset
        self.length = length
        self.stored_crc = stored_crc
        self.payload = payload
        self.crc_ok = zlib.crc32(payload) & 0xFFFFFFFF == stored_crc
        self.record = None


class JournalImage:
    """Result of parsing a raw journal byte image."""

    def __init__(self):
        self.header_ok = False
        self.header_error = None
        self.base = None
        self.frames = []          # intact (CRC-valid) frames
        self.broken = None        # first structural problem
        self.tail_bytes = 0       # incomplete trailing bytes
        self.tail_offset = None   # file offset where the tail begins
        self.records = []         # records from intact frames in order
        self.commits = []         # commit records with writes
        self.sequence_end = None  # last contiguous record sequence
        self.empty = False

    def summary(self):
        kinds = {}
        for r in self.records:
            kinds[r.get("kind", "?")] = kinds.get(r.get("kind", "?"), 0) + 1
        return {
            "header_ok": self.header_ok,
            "header_error": self.header_error,
            "base": self.base,
            "intact_frames": len(self.frames),
            "tail_bytes": self.tail_bytes,
            "broken": self.broken,
            "record_kinds": kinds,
            "sequence_end": self.sequence_end,
            "commit_sequences": [c["sequence"] for c in self.commits if c.get("writes")],
        }


def parse(data):
    """Parse a raw journal byte image into a JournalImage (never raises)."""
    img = JournalImage()
    if len(data) == 0:
        # LaminaDB treats a zero-length journal as an uninitialised file and
        # writes a fresh header on open (journal.Open: size==0 -> header).
        # The model records this separately from "truncated header".
        img.header_error = "empty file (fresh journal)"
        img.empty = True
        return img
    if len(data) < HEADER:
        img.header_error = f"image shorter than header ({len(data)} bytes)"
        img.tail_bytes = len(data)
        img.tail_offset = 0
        return img
    magic, base, stored = struct.unpack(">4sQI", data[:HEADER])
    if magic != b"LMW1":
        img.header_error = f"bad magic {magic!r}"
        return img
    if zlib.crc32(data[:12]) & 0xFFFFFFFF != stored:
        img.header_error = "header crc mismatch"
        return img
    img.header_ok = True
    img.base = base
    off = HEADER
    expect = base + 1
    while off < len(data):
        if off + 8 > len(data):
            img.tail_bytes = len(data) - off
            img.tail_offset = off
            break
        length, crc = struct.unpack(">II", data[off:off + 8])
        if length == 0 or length > MAX_FRAME:
            img.broken = f"invalid frame length {length} at offset {off}"
            img.tail_bytes = len(data) - off
            img.tail_offset = off
            break
        if off + 8 + length > len(data):
            img.tail_bytes = len(data) - off
            img.tail_offset = off
            break
        payload = data[off + 8:off + 8 + length]
        f = Frame(off, length, crc, payload)
        if not f.crc_ok:
            img.broken = f"crc mismatch at offset {off} (frame {len(img.frames) + 1})"
            img.tail_bytes = len(data) - off
            img.tail_offset = off
            break
        try:
            rec = json.loads(payload)
        except Exception as exc:  # pragma: no cover - defensive
            img.broken = f"json error at offset {off}: {exc}"
            img.tail_bytes = len(data) - off
            img.tail_offset = off
            break
        if rec.get("format") != 1:
            img.broken = f"format {rec.get('format')} at offset {off}"
            img.tail_bytes = len(data) - off
            img.tail_offset = off
            break
        if rec.get("sequence") != expect:
            img.broken = (f"sequence discontinuity at offset {off}: "
                          f"expected {expect}, found {rec.get('sequence')}")
            img.tail_bytes = len(data) - off
            img.tail_offset = off
            break
        f.record = rec
        img.frames.append(f)
        img.records.append(rec)
        expect += 1
        off += 8 + length
    img.sequence_end = expect - 1 if img.header_ok else None
    img.commits = [r for r in img.records if r.get("kind") == "commit"]
    return img


def parse_file(path):
    with open(path, "rb") as fh:
        return parse(fh.read())


def write_frame(payload_obj, base, seq):
    """Build one journal frame exactly as the documented format specifies."""
    rec = dict(payload_obj)
    rec["format"] = 1
    rec["sequence"] = seq
    payload = json.dumps(rec, separators=(",", ":"), sort_keys=False).encode()
    return struct.pack(">II", len(payload), zlib.crc32(payload) & 0xFFFFFFFF) + payload


def build_journal(base, records):
    """Synthesize a journal image from records (used by oracle tests)."""
    hdr = struct.pack(">4sQI", b"LMW1", base, 0)
    hdr = hdr[:12]
    hdr += struct.pack(">I", zlib.crc32(hdr) & 0xFFFFFFFF)
    out = bytearray(hdr)
    for i, rec in enumerate(records, start=1):
        out += write_frame(rec, base, base + i)
    return bytes(out)


def replay(records, relation):
    """Independent replay of commit records into {seq: {key: row}} snapshots.

    Mirrors the documented semantics only: a commit record applies all of its
    mutations atomically at its sequence; tombstones remove a key. Catalog
    records are ignored here (handled by callers).

    Returns (snapshots, created_seq). snapshots[s] is the visible row set after
    applying every commit with sequence <= s.
    """
    snapshots = {}
    rows = {}
    for rec in records:
        seq = rec["sequence"]
        if rec.get("kind") == "commit":
            for m in rec.get("writes") or []:
                if m.get("relation") != relation:
                    continue
                if m.get("deleted"):
                    rows.pop(m["key"], None)
                else:
                    rows[m["key"]] = dict(m.get("row") or {})
        snapshots[seq] = {k: dict(v) for k, v in rows.items()}
    return snapshots


def all_snapshot_sequences(records):
    return [r["sequence"] for r in records]


def rows_to_values(rows):
    """Map key -> row into primary-value -> row using the schema's primary."""
    out = {}
    for key, row in rows.items():
        # key is like "int:7" / "text:\"x\""; the row carries the real value.
        out[key] = row
    return out
