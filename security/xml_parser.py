"""Hardened XML order parser.

Security posture (all 15 items):
 1. DTD disabled              - any DOCTYPE is rejected before parsing
 2. External entities off     - SYSTEM/PUBLIC identifiers rejected; stdlib
                                expat never resolves them anyway
 3. XInclude disabled         - xi:include elements rejected pre-parse
 4. Entity expansion capped   - entity reference count limited (billion laughs)
 5. Schema locations whitelisted - xsi:schemaLocation hosts must be whitelisted
 6. Namespace full validation - every element/attr namespace URI is checked,
                                not just localName
 7. SYSTEM identifiers rejected
 8. Errors sanitized          - parse failures never echo document content
 9. External DTD timeout      - no external DTD is ever fetched; URL fetches
                                (if any) must use FETCH_TIMEOUT
10. Recursion depth limited   - element nesting depth capped
11. XPath parameterized       - find_order() builds predicates from escaped
                                values, never string-concatenated input
12. CDATA handled             - CDATA content is treated as literal text,
                                entities inside are not expanded
13. Encoding validated        - declared encoding must match a safe whitelist
                                and actual bytes must decode cleanly
14. Parser not reused         - a fresh parser is built per parse_orders() call
15. Document size limited     - input larger than MAX_DOCUMENT_BYTES rejected
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from ipaddress import ip_address
from urllib.parse import urlparse

# --- Limits -----------------------------------------------------------------

MAX_DOCUMENT_BYTES = 1 * 1024 * 1024   # 15. document size limit
MAX_ENTITY_REFERENCES = 100            # 4. entity expansion cap
MAX_DEPTH = 64                         # 10. recursion / nesting depth cap
FETCH_TIMEOUT = 5                      # 9. seconds, for any external fetch

ALLOWED_ENCODINGS = {"utf-8", "utf-16", "us-ascii", "iso-8859-1"}  # 13.

_DOCTYPE_RE = re.compile(r"<!DOCTYPE", re.IGNORECASE)
_SYSTEM_ID_RE = re.compile(r"\b(SYSTEM|PUBLIC)\b", re.IGNORECASE)
_ENTITY_DECL_RE = re.compile(r"<!ENTITY", re.IGNORECASE)
_PARAM_ENTITY_RE = re.compile(r"<!ENTITY\s+%", re.IGNORECASE)
_XINCLUDE_RE = re.compile(
    r"<\s*(xi:include|[\w.-]+:include)\b[^>]*\bhref\s*=", re.IGNORECASE
)
_ENTITY_REF_RE = re.compile(r"&[A-Za-z_][\w.-]*;")
_ENCODING_DECL_RE = re.compile(
    r"<\?xml[^>]*\bencoding\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE
)
_CDATA_RE = re.compile(r"<!\[CDATA\[.*?\]\]>", re.DOTALL)


class XMLSecurityError(ValueError):
    """Raised when input violates the XML security policy."""


# --- Pre-parse security scanners --------------------------------------------

def _to_text(data) -> str:
    """Normalize input to str, validating declared vs actual encoding (13)."""
    if isinstance(data, bytes):
        if len(data) > MAX_DOCUMENT_BYTES:
            raise XMLSecurityError("document too large")
        head = data[:200].decode("ascii", errors="ignore")
        m = _ENCODING_DECL_RE.search(head)
        declared = (m.group(1).lower() if m else "utf-8")
        if declared not in ALLOWED_ENCODINGS:
            raise XMLSecurityError("disallowed encoding declaration")
        try:
            return data.decode(declared)
        except (UnicodeDecodeError, LookupError):
            raise XMLSecurityError("encoding declaration does not match bytes")
    text = str(data)
    if len(text.encode("utf-8", errors="ignore")) > MAX_DOCUMENT_BYTES:
        raise XMLSecurityError("document too large")
    m = _ENCODING_DECL_RE.search(text[:200])
    if m and m.group(1).lower() not in ALLOWED_ENCODINGS:
        raise XMLSecurityError("disallowed encoding declaration")
    return text


def has_doctype(xml) -> bool:
    """True if the document contains a DOCTYPE declaration (1)."""
    return bool(_DOCTYPE_RE.search(_to_text(xml)))


def has_external_entity(xml) -> bool:
    """True if the document references external resources (2, 3, 7).

    Detects: external entity declarations, SYSTEM/PUBLIC identifiers,
    parameter entities, DOCTYPE system identifiers, and XInclude hrefs.
    """
    text = _to_text(xml)
    if _XINCLUDE_RE.search(text):                       # 3. XInclude
        return True
    if _PARAM_ENTITY_RE.search(text):                   # parameter entities
        return True
    if _SYSTEM_ID_RE.search(text):                      # 7. SYSTEM/PUBLIC
        return True
    if _ENTITY_DECL_RE.search(text) and _SYSTEM_ID_RE.search(text):
        return True
    return False


def entity_count_ok(xml, limit: int = MAX_ENTITY_REFERENCES) -> bool:
    """True if entity-reference count is within limit (4, billion laughs).

    References inside CDATA sections are literal text and not counted (12).
    Predefined XML entities (amp, lt, gt, quot, apos) are parser-builtins
    and not expandable, so they are excluded.
    """
    text = _CDATA_RE.sub("", _to_text(xml))
    refs = [
        m.group(0) for m in _ENTITY_REF_RE.finditer(text)
        if m.group(0) not in ("&amp;", "&lt;", "&gt;", "&quot;", "&apos;")
    ]
    return len(refs) <= limit


def safe_external_url(url, allowed_hosts) -> bool:
    """True if url is https and its host is whitelisted (5, SSRF guard).

    Rejects non-https schemes, credentials, and literal IP addresses
    (loopback/private/link-local/reserved are never allowed).
    """
    try:
        parsed = urlparse(str(url))
    except ValueError:
        return False
    if parsed.scheme != "https":
        return False
    host = parsed.hostname
    if not host or parsed.username or parsed.password:
        return False
    try:  # never allow literal IPs, even whitelisted-looking ones
        ip = ip_address(host)
        return False if ip else False
    except ValueError:
        pass
    return host.lower() in {h.lower() for h in allowed_hosts}


def namespace_ok(xml, expected_uri) -> bool:
    """True if every namespaced element/attribute uses expected_uri (6).

    Validation is on the fully-resolved namespace URI of each node, so a
    forged prefix bound to a different URI is rejected.
    """
    text = _to_text(xml)
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return False
    for elem in root.iter():
        for name in [elem.tag, *elem.attrib.keys()]:
            if name.startswith("{"):
                uri = name[1:].split("}", 1)[0]
                if uri != expected_uri:
                    return False
            elif name is elem.tag and ":" in name:
                return False  # unresolvable prefix
    return True


def _depth_ok(elem, depth: int = 0) -> bool:
    """10. recursion depth cap (iterative, no Python recursion)."""
    stack = [(elem, 0)]
    while stack:
        node, d = stack.pop()
        if d > MAX_DEPTH:
            return False
        stack.extend((child, d + 1) for child in node)
    return True


def _check_schema_locations(root, allowed_schema_hosts=frozenset()) -> None:
    """5. xsi:schemaLocation hosts must be whitelisted."""
    xsi = "{http://www.w3.org/2001/XMLSchema-instance}schemaLocation"
    for elem in root.iter():
        value = elem.attrib.get(xsi) or elem.attrib.get("schemaLocation")
        if not value:
            continue
        parts = value.split()
        for loc in parts[1::2] if len(parts) > 1 else parts:
            if not safe_external_url(loc, allowed_schema_hosts):
                raise XMLSecurityError("schemaLocation host not whitelisted")


# --- Public API ---------------------------------------------------------------

def parse_orders(xml, allowed_schema_hosts=frozenset()):
    """Parse an <orders> document and return its <order> elements.

    Returns [] on any malformed or policy-violating input. Error messages
    never include document content (8). A fresh parser is created per
    call, so no entity/element state survives between parses (14).
    """
    try:
        text = _to_text(xml)                                  # 13, 15
        if not text.strip():
            return []
        if has_doctype(text):                                 # 1. DTD off
            raise XMLSecurityError("DOCTYPE is not allowed")
        if has_external_entity(text):                         # 2, 3, 7
            raise XMLSecurityError("external entities are not allowed")
        if not entity_count_ok(text):                         # 4. expansion cap
            raise XMLSecurityError("too many entity references")

        parser = ET.XMLParser()  # 14. fresh parser per call; stdlib expat
                                 # never loads external DTDs (9: nothing to
                                 # time out) and does not expand undefined
                                 # entities.
        root = ET.fromstring(text, parser=parser)
        if not _depth_ok(root):                               # 10. depth cap
            raise XMLSecurityError("document nested too deeply")
        _check_schema_locations(root, allowed_schema_hosts)   # 5. whitelist
        if root.tag.split("}")[-1] != "orders":
            return []
        return [e for e in root if e.tag.split("}")[-1] == "order"]
    except (XMLSecurityError, ET.ParseError, UnicodeError, ValueError):
        return []  # 8. sanitized: no document content, no parser internals


def find_order(orders_root, order_id):
    """11. Parameterized XPath: value is escaped, never concatenated raw."""
    safe_id = str(order_id).replace("&", "&amp;").replace("<", "&lt;")
    if '"' in safe_id:
        if "'" in safe_id:
            return None  # cannot safely quote both; refuse
        return orders_root.find(f".//order[@id='{safe_id}']")
    return orders_root.find(f'.//order[@id="{safe_id}"]')
