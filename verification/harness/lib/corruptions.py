"""Byte-level damage applied to a completed data directory (no live process).

Each mutator is deterministic and documented, so each row of the matrix is
reproducible from the recorded seed bytes.
"""
import json
import os
import struct
import zlib

import imagemodel


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def _write(path, data):
    with open(path, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    fd = os.open(os.path.dirname(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _last_frame_offset(data):
    """Return (offset, length) of the last intact frame."""
    off = 16
    last = None
    while off + 8 <= len(data):
        length = struct.unpack(">I", data[off:off + 4])[0]
        if length == 0 or off + 8 + length > len(data):
            break
        last = (off, length)
        off += 8 + length
    if last is None:
        raise ValueError("no frame found")
    return last


def journal_crc_flip(data_dir, ctx):
    """Flip one payload byte of the last frame; CRC must now mismatch."""
    path = os.path.join(data_dir, "journal.lmw")
    data = bytearray(_read(path))
    off, length = _last_frame_offset(bytes(data))
    target = off + 8 + length // 2
    ctx.record("mutated_offset", target)
    data[target] ^= 0xFF
    _write(path, bytes(data))


def journal_length_zero(data_dir, ctx):
    """Set the last frame's length field to zero (illegal)."""
    path = os.path.join(data_dir, "journal.lmw")
    data = bytearray(_read(path))
    off, _ = _last_frame_offset(bytes(data))
    ctx.record("mutated_offset", off)
    data[off:off + 4] = struct.pack(">I", 0)
    _write(path, bytes(data))


def journal_sequence_gap(data_dir, ctx):
    """Rewrite a frame's sequence to skip a number, repairing its CRC.

    The bytes are internally consistent as a frame; only the documented
    contiguity invariant is violated.
    """
    path = os.path.join(data_dir, "journal.lmw")
    data = bytearray(_read(path))
    off = 16
    frames = []
    while off + 8 <= len(data):
        length = struct.unpack(">I", data[off:off + 4])[0]
        if length == 0 or off + 8 + length > len(data):
            break
        frames.append((off, length))
        off += 8 + length
    if len(frames) < 2:
        raise ValueError("need at least two frames")
    off, length = frames[-1]
    payload = json.loads(bytes(data[off + 8:off + 8 + length]))
    payload["sequence"] = payload["sequence"] + 1
    raw = json.dumps(payload, separators=(",", ":")).encode()
    frame = struct.pack(">II", len(raw), zlib.crc32(raw) & 0xFFFFFFFF) + raw
    data[off:off + 8 + length] = frame
    ctx.record("mutated_offset", off)
    ctx.record("mutated_sequence", payload["sequence"])
    _write(path, bytes(data))


def journal_header_truncated(data_dir, ctx):
    path = os.path.join(data_dir, "journal.lmw")
    data = _read(path)
    ctx.record("truncated_to", 10)
    _write(path, data[:10])


def journal_header_base_ahead(data_dir, ctx):
    """Make the journal claim it needs a newer checkpoint than exists."""
    path = os.path.join(data_dir, "journal.lmw")
    data = bytearray(_read(path))
    base = struct.unpack(">Q", data[4:12])[0]
    new_base = base + 1000
    data[4:12] = struct.pack(">Q", new_base)
    data[12:16] = struct.pack(">I", zlib.crc32(bytes(data[:12])) & 0xFFFFFFFF)
    ctx.record("journal_base_before", base)
    ctx.record("journal_base_after", new_base)
    _write(path, bytes(data))


def journal_tail_garbage(data_dir, ctx):
    """Append an incomplete frame. Documented behaviour: truncate and start."""
    path = os.path.join(data_dir, "journal.lmw")
    data = _read(path)
    garbage = b"\x00\x00\x00"
    ctx.record("appended_tail_bytes", len(garbage))
    _write(path, data + garbage)


def checkpoint_digest_mismatch(data_dir, ctx):
    """Change one payload byte and leave the recorded digest stale."""
    path = os.path.join(data_dir, "checkpoint.lmi")
    data = bytearray(_read(path))
    # locate the payload object and flip a byte inside it that keeps the text
    # valid UTF-8/JSON (a digit in "sequence":N).
    text = bytes(data)
    idx = text.find(b'"sequence":')
    if idx < 0:
        raise ValueError("sequence field not found")
    pos = idx + len(b'"sequence":')
    while pos < len(text) and not (0x30 <= text[pos] <= 0x39):
        pos += 1
    if pos >= len(text):
        raise ValueError("sequence digit not found")
    data[pos] = 0x30 if data[pos] != 0x30 else 0x31
    ctx.record("mutated_offset", pos)
    _write(path, bytes(data))


def _rewrite_image(data_dir, ctx, mutate, label):
    path = os.path.join(data_dir, "checkpoint.lmi")
    image = imagemodel.decode(_read(path))
    mutate(image)
    out = imagemodel.encode(image)
    ctx.record("checkpoint_semantic_mutation", label)
    _write(path, out)


def checkpoint_row_type(data_dir, ctx):
    def mutate(image):
        table = image["store"]["tables"][list(image["store"]["tables"])[0]]
        key = sorted(table)[0]
        table[key][-1]["row"] = dict(table[key][-1]["row"])
        primary = image["catalog"]["relations"][
            list(image["catalog"]["relations"])[0]]["primary"]
        table[key][-1]["row"][primary] = "not-an-int"
    _rewrite_image(data_dir, ctx, mutate, "row primary type changed to text")


def checkpoint_version_order(data_dir, ctx):
    def mutate(image):
        table = image["store"]["tables"][list(image["store"]["tables"])[0]]
        key = sorted(table)[0]
        chain = table[key]
        if len(chain) < 2:
            # duplicate the last version with an earlier sequence
            chain.append(dict(chain[-1]))
        chain.insert(0, dict(chain[-1]))
        chain[0]["sequence"] = 0
    _rewrite_image(data_dir, ctx, mutate, "version sequence 0 (invalid order)")


def checkpoint_unknown_relation(data_dir, ctx):
    def mutate(image):
        image["store"]["tables"]["ghost"] = {}
    _rewrite_image(data_dir, ctx, mutate, "store references unknown relation")


def checkpoint_catalog_sequence(data_dir, ctx):
    def mutate(image):
        name = next(iter(image["catalog"]["relations"]))
        image["catalog"]["relations"][name]["created"] = 0
    _rewrite_image(data_dir, ctx, mutate, "relation created sequence 0")


def checkpoint_unique_violation(data_dir, ctx):
    def mutate(image):
        rel = next(iter(image["catalog"]["relations"]))
        columns = [c["name"] for c in image["catalog"]["relations"][rel]["columns"]]
        primary = image["catalog"]["relations"][rel]["primary"]
        # Pick a non-primary, non-boolean column; strings and ints both work.
        column = next(c for c in columns
                      if c != primary and
                      next(col["type"] for col in
                           image["catalog"]["relations"][rel]["columns"]
                           if col["name"] == c) != "bool")
        image["catalog"]["indexes"]["uniq"] = {
            "name": "uniq",
            "relation": rel,
            "column": column,
            "unique": True,
            "created": image["sequence"],
        }
        table = image["store"]["tables"][rel]
        keys = sorted(table)
        if len(keys) < 2:
            raise ValueError("need two rows")
        table[keys[1]][-1]["row"] = dict(table[keys[1]][-1]["row"])
        table[keys[1]][-1]["row"][column] = table[keys[0]][-1]["row"][column]
    _rewrite_image(data_dir, ctx, mutate, "two current rows share a unique value")


def checkpoint_removed(data_dir, ctx):
    path = os.path.join(data_dir, "checkpoint.lmi")
    os.unlink(path)
    ctx.record("checkpoint_removed", True)


def journal_removed(data_dir, ctx):
    path = os.path.join(data_dir, "journal.lmw")
    os.unlink(path)
    ctx.record("journal_removed", True)
