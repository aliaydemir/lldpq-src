"""Shared management-address handling for IPv4, IPv6 and existing SSH aliases.

``normalize_address`` is the validation boundary.  The family and sort helpers
also accept older display values so a missing address cannot break an otherwise
usable inventory/report.  No DNS resolution or network access happens here.
"""

from __future__ import annotations

import ipaddress
import re


_HOST_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_ZONE_PATTERN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
_DOTTED_NUMBER_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+){3}")


def normalize_address(value, *, allow_hostname=False):
    """Return a canonical connection address, or raise ``ValueError``.

    IPv6 literals use compressed lowercase notation, without URL brackets.
    Link-local IPv6 needs an explicit local interface/zone, e.g.
    ``fe80::1%eth0``.  Zone spelling is preserved because interface names are
    case sensitive.  ``allow_hostname`` retains the existing inventory's safe
    DNS names and SSH aliases without resolving or changing their spelling.
    """
    if not isinstance(value, str):
        raise ValueError("Address must be a string")
    value = value.strip()
    if not value or any(character.isspace() for character in value):
        raise ValueError("Address must not be empty or contain whitespace")
    literal, separator, zone = value.partition("%")
    if separator and (":" not in literal or not _ZONE_PATTERN.fullmatch(zone)):
        raise ValueError("IPv6 scope must be a local interface name or numeric zone")
    try:
        address = ipaddress.ip_address(literal)
    except ValueError:
        # Colons/scopes always indicate an attempted IP literal.  Do not turn
        # a mistyped IPv6 or dotted IPv4 address into an SSH hostname instead.
        if (allow_hostname and not separator and ":" not in value
                and not _DOTTED_NUMBER_PATTERN.fullmatch(value)
                and _HOST_PATTERN.fullmatch(value)):
            return value
        raise ValueError(f"Invalid IP address: {value!r}") from None
    if address.version == 6:
        if address.is_link_local and not separator:
            raise ValueError("Link-local IPv6 requires a local interface (for example fe80::1%eth0)")
        # Python versions differ on how they render mapped IPv4 literals.
        # Choose one spelling so upgrades do not change inventory identities.
        canonical = f"::ffff:{address.ipv4_mapped}" if address.ipv4_mapped is not None else address.compressed
        return f"{canonical}%{zone}" if separator else canonical
    if separator:
        raise ValueError("IPv4 addresses cannot have an IPv6 scope")
    return str(address)


def address_family(value):
    """Return 4/6 for an IP literal, or 0 for a hostname/missing/invalid value.

    This classifies address families; use ``normalize_address`` to validate a
    destination before connecting, especially for a scoped link-local address.
    """
    try:
        return ipaddress.ip_address(str(value).strip().partition("%")[0]).version
    except ValueError:
        return 0


def address_sort_key(value):
    """Return a comparable ``(family, numeric_address, scope_or_name)`` tuple.

    Names/missing values sort before IPv4 then IPv6.  IPv6 is sorted by numeric
    address, not by the spelling of its compressed representation.
    """
    text = "" if value is None else str(value).strip()
    literal, _separator, zone = text.partition("%")
    try:
        address = ipaddress.ip_address(literal)
    except ValueError:
        return (0, 0, text.casefold())
    return (address.version, int(address), zone)
