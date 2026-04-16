# PyFLP - FL Studio project file parser
# See pyproject.toml for license (GPL-3.0).

"""Opcode-classification overrides for FL Studio 25+.

FL 25 introduced events that do not follow the classic opcode-range rules
baked into :mod:`pyflp._events`:

* ``0-63``    → BYTE    (1-byte payload)
* ``64-127``  → WORD    (2-byte payload)
* ``128-191`` → DWORD   (4-byte payload)
* ``192-255`` → DATA    (VarInt size + payload)

Known violations so far are catalogued here. Each entry explicitly pins
both the size rule (how to read bytes off the stream) and the event
class (how to interpret them), taking precedence over the range-based
fallback when the FLP header reports FL major version >= 25.

Discovery methodology and evidence: ``docs/fl25-event-format.md`` in the
flpdiff repo. New overrides are added only when backed by a reproducible
harness sweep — never on speculation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SizeRule = Literal["byte", "word", "dword", "data", "utf16_zterm"]
"""Payload-size rule for an opcode.

* ``byte``         — 1-byte payload
* ``word``         — 2-byte payload (little-endian)
* ``dword``        — 4-byte payload (little-endian)
* ``data``         — VarInt size prefix + N-byte payload
* ``utf16_zterm``  — UTF-16-LE string, no size prefix, terminated by
  a zero UTF-16 code unit (``00 00``) at an even offset. The
  terminator is included in the payload (caller can strip). This
  is FL 25's preferred encoding for short metadata strings like the
  full product/version label — see ``docs/fl25-event-format.md``.
"""


@dataclass(frozen=True)
class OpcodeOverride:
    """Explicit classification for one opcode on FL 25+."""

    size_rule: SizeRule
    #: Event class name (resolved at dispatch time) to decode the
    #: payload. ``None`` means "use the range-based default class"
    #: — useful when only the size rule needs overriding.
    event_class_name: str | None = None


# Opcode -> override. Keep this table tight: empirical evidence only.
FL25_OVERRIDES: dict[int, OpcodeOverride] = {
    # 0x36 (54 decimal) carries the FL version string — e.g.
    # "FL Studio Producer Edition v25.2.4\0" — as null-terminated
    # UTF-16-LE with NO size prefix. Classic rule puts 0x36 in BYTE
    # range with 1-byte payload, which fragments the string into
    # bogus single-character "events" and corrupts the rest of the
    # event stream.
    #
    # First discovered attempt used VarInt sizing — it worked by
    # coincidence on the base fixtures because the string's first
    # byte 'F' (0x46) equals the actual payload length (70 bytes),
    # but that's an ASCII accident. The real encoding is
    # null-terminated UTF-16.
    #
    # Decoded as UnknownDataEvent (raw bytes). PyFLP's string event
    # classes restrict ALLOWED_IDS to the TEXT range (192-207); a
    # follow-up can introduce a looser string event class.
    0x36: OpcodeOverride(size_rule="utf16_zterm", event_class_name="UnknownDataEvent"),
    # 0xC0 (192) was ChannelID._Name (deprecated UTF-16 channel name)
    # through FL 24. In FL 25 it carries a compound project-properties
    # blob that is not UTF-16. It's already in the DATA range so the
    # size rule is correct; only the decoder needs to change from the
    # string-default fallback to opaque.
    0xC0: OpcodeOverride(size_rule="data", event_class_name="UnknownDataEvent"),
}


__all__ = ["FL25_OVERRIDES", "OpcodeOverride", "SizeRule"]
