"""Independent recovery oracle for LaminaDB data directories.

Given the raw bytes of a data directory (checkpoint.lmi, journal.lmw, and any
stray temp files), decide from the documented format and invariants:

  * whether a correct instance must start or must refuse to start,
  * which rows and catalog it must expose if it starts,
  * how many bytes of incomplete tail may be truncated,
  * which commits are present in the durable byte image.

The harness compares the server's actual exposure against this oracle; the
server's success is never used as the only proof. This module does not import
or execute any LaminaDB code.
"""
import os
import pathlib

import imagemodel
import journalmodel


class Verdict:
    START = "start"
    REFUSE = "refuse"

    def __init__(self, outcome, reason="", state=None, tail_bytes=0,
                 durable_sequences=(), checkpoint_valid=None):
        self.outcome = outcome
        self.reason = reason
        self.state = state or {"relations": {}, "rows": {}}
        self.tail_bytes = tail_bytes
        self.durable_sequences = list(durable_sequences)
        self.checkpoint_valid = checkpoint_valid
        self.head = None
        self.image_sequence = None
        self.journal_sequence_end = None

    def as_dict(self):
        return {
            "outcome": self.outcome,
            "head": getattr(self, "head", None),
            "image_sequence": getattr(self, "image_sequence", None),
            "journal_sequence_end": self.journal_sequence_end,
            "reason": self.reason,
            "tail_bytes": self.tail_bytes,
            "durable_sequences": self.durable_sequences,
            "checkpoint_valid": self.checkpoint_valid,
            "relations": sorted(self.state.get("relations", {})),
            "rows": {rel: sorted(rows) for rel, rows in
                     sorted(self.state.get("rows", {}).items())},
        }


def _journal_path(directory):
    return pathlib.Path(directory) / "journal.lmw"


def _checkpoint_path(directory):
    return pathlib.Path(directory) / "checkpoint.lmi"


def _apply_records(state, records, after, image=None):
    """Apply journal records with sequence > after on top of `state`.

    state = {"relations": {name: relation_def}, "rows": {name: {key: row}}}
    """
    relations = dict(state.get("relations", {}))
    rows = {name: dict(table) for name, table in state.get("rows", {}).items()}
    for rec in records:
        seq = rec.get("sequence")
        if seq <= after:
            continue
        kind = rec.get("kind")
        if kind == "relation":
            rel = rec.get("relation") or {}
            relations[rel.get("name")] = rel
            rows.setdefault(rel.get("name"), {})
        elif kind == "index":
            pass  # index definitions do not change visible rows
        elif kind == "commit":
            for m in rec.get("writes") or []:
                table = rows.setdefault(m.get("relation"), {})
                if m.get("deleted"):
                    table.pop(m.get("key"), None)
                else:
                    table[m.get("key")] = dict(m.get("row") or {})
        elif kind == "vacuum":
            pass  # current visible rows are unchanged by vacuum
    return {"relations": relations, "rows": rows}


def _from_image(image):
    relations = dict(image.get("catalog", {}).get("relations", {}))
    rows = {}
    for rel, table in (image.get("store", {}).get("tables") or {}).items():
        rows[rel] = {}
        for key in table:
            version = imagemodel.visible(table[key], image["sequence"])
            if version is None or version.get("deleted"):
                continue
            rows[rel][key] = dict(version["row"])
    return {"relations": relations, "rows": rows}


def inspect(directory):
    """Inspect a data directory and return (Verdict, journal_image, image)."""
    directory = pathlib.Path(directory)
    jpath = _journal_path(directory)
    cpath = _checkpoint_path(directory)

    if not jpath.exists():
        if cpath.exists():
            return Verdict(Verdict.REFUSE,
                           "checkpoint without journal"), None, None
        return Verdict(Verdict.START,
                       "fresh data directory; no journal or checkpoint"), None, None

    journal = journalmodel.parse_file(jpath)
    if journal.empty:
        # A zero-length journal.lmw is what an interrupted creation (restore,
        # or first open) leaves behind. LaminaDB initialises it as a fresh
        # journal; the model follows that, but callers must treat a *restore*
        # that leaves one as "installed nothing", which the restore classifier
        # reports separately.
        if cpath.exists():
            return Verdict(Verdict.REFUSE,
                           "empty journal alongside a checkpoint"), journal, None
        return Verdict(Verdict.START,
                       "zero-length journal treated as a fresh journal",
                       state={"relations": {}, "rows": {}}), journal, None
    if not journal.header_ok:
        return Verdict(Verdict.REFUSE,
                       f"journal header invalid: {journal.header_error}"), journal, None
    if journal.broken:
        return Verdict(Verdict.REFUSE, f"journal invalid: {journal.broken}",
                       ), journal, None

    image = None
    checkpoint_valid = None
    if cpath.exists():
        try:
            image = imagemodel.read(cpath)
            checkpoint_valid = True
        except imagemodel.ImageError as exc:
            return Verdict(Verdict.REFUSE, f"checkpoint invalid: {exc}",
                           checkpoint_valid=False), journal, None
    else:
        checkpoint_valid = False

    image_seq = image["sequence"] if image else 0
    if image is None and journal.base > 0:
        # A journal whose header records a checkpoint base newer than "no
        # checkpoint" is missing the state that base stands for. LaminaDB
        # documents this as "journal requires newer checkpoint"; the oracle
        # derives the same conclusion from the header alone.
        return Verdict(Verdict.REFUSE,
                       f"journal requires checkpoint at base {journal.base}, "
                       f"but none is installed",
                       checkpoint_valid=None), journal, None
    if image is not None and journal.base > image_seq:
        return Verdict(Verdict.REFUSE,
                       f"journal requires newer checkpoint "
                       f"(journal base {journal.base} > checkpoint {image_seq})",
                       checkpoint_valid=True), journal, image
    last = journal.base + len(journal.records)
    if image_seq > last:
        return Verdict(Verdict.REFUSE,
                       f"checkpoint ahead of journal "
                       f"(checkpoint {image_seq} > last record {last})",
                       checkpoint_valid=True), journal, image

    try:
        if image is not None:
            state = _from_image(image)
        else:
            state = {"relations": {}, "rows": {}}
        state = _apply_records(state, journal.records, image_seq)
    except Exception as exc:
        return Verdict(Verdict.REFUSE, f"replay error: {exc}",
                       checkpoint_valid=checkpoint_valid), journal, image

    # Unique-index constraints are enforced over the final visible state.
    try:
        _check_unique(image, state)
    except imagemodel.ImageError as exc:
        return Verdict(Verdict.REFUSE, f"recovered constraints: {exc}",
                       checkpoint_valid=checkpoint_valid), journal, image

    durable = [c["sequence"] for c in journal.commits if c.get("writes")]
    head = max(image_seq, last)
    verdict = Verdict(
        Verdict.START,
        reason=("journal tail of %d bytes will be truncated" % journal.tail_bytes)
        if journal.tail_bytes else "clean recovery",
        state=state,
        tail_bytes=journal.tail_bytes,
        durable_sequences=durable,
        checkpoint_valid=checkpoint_valid,
    )
    verdict.head = head
    verdict.image_sequence = image_seq
    verdict.journal_sequence_end = journal.sequence_end
    return verdict, journal, image


def _check_unique(image, state):
    indexes = {}
    if image is not None:
        for name, definition in (image.get("catalog", {}).get("indexes") or {}).items():
            indexes[name] = definition
    relations = state.get("relations", {})
    for definition in indexes.values():
        if not definition.get("unique"):
            continue
        rel = relations.get(definition["relation"])
        if rel is None:
            continue
        seen = {}
        for key, row in state["rows"].get(definition["relation"], {}).items():
            value = row.get(definition["column"])
            if value is None:
                continue
            token = imagemodel.key_of(value)
            if token in seen and seen[token] != key:
                raise imagemodel.ImageError(
                    f"unique constraint {definition['name']} violated")
            seen[token] = key


def durable_max(directory):
    """Highest sequence whose commit frame is provably on disk, and its rows.

    This is the client-visible floor a correct instance must expose even if
    the process died before responding. It is independent of any checkpoint.
    """
    verdict, journal, image = inspect(directory)
    if verdict.outcome != Verdict.START or journal is None:
        return verdict, None, None
    commits = [c["sequence"] for c in journal.commits if c.get("writes")]
    if not commits:
        return verdict, (getattr(verdict, "image_sequence", 0) or 0), {}
    snapshots = journalmodel.replay(journal.records, "spectra")
    best = None
    for seq in sorted(commits):
        if seq in snapshots:
            best = seq
    if best is None:
        return verdict, None, {}
    floor = getattr(verdict, "image_sequence", 0) or 0
    at = max(best, floor)
    return verdict, at, snapshots.get(best, {})


def image_matches_journal(image, journal):
    """Checkpoint must equal an independent replay of the journal at its
    sequence. Returns (ok, detail)."""
    replay_image = imagemodel.visible_rows
    at = image["sequence"]
    journal_state = _apply_records({"relations": {}, "rows": {}}, journal.records, 0)
    image_state = _from_image(image)
    expected = {"relations": {}, "rows": {}}
    # replay from empty and cut at `at`
    expected = _apply_records({"relations": {}, "rows": {}},
                              [r for r in journal.records if r["sequence"] <= at], 0)
    if image_state["rows"] != expected["rows"]:
        return False, "checkpoint rows differ from journal replay at its sequence"
    return True, "checkpoint rows equal journal replay at its sequence"
