import ipaddress
import re
from collections import Counter
from pathlib import Path

from pypdf import PdfReader


# --------------------------------------------------
# LIMITS
# --------------------------------------------------

MAX_PDF_BYTES = 15 * 1024 * 1024
MAX_PAGES = 100
MAX_EXTRACTED_CHARACTERS = 2_000_000
MAX_FINDINGS = 5000
MAX_URL_LENGTH = 2048
MAX_DOMAIN_LENGTH = 253
MAX_EVIDENCE_PER_GROUP = 5

EVIDENCE_RADIUS = 100
TRAILING_PUNCTUATION = ".,;:)]}"

# ATT&CK evidence is row-aware (see attack_evidence) instead of a fixed
# character window, so neighbouring table rows are not mixed in.
MAX_ATTACK_EVIDENCE_CHARS = 240
MIN_ATTACK_EVIDENCE_CHARS = 60
MAX_ATTACK_EXTRA_LINES = 2
MIN_ATTACK_SEGMENT_CHARS = 8

# Set to False to disable rejoining of hashes wrapped across lines.
REPAIR_WRAPPED_HASHES = True

# A wrapped hash whose first piece is already a valid hash length (32 or 40
# characters) is indistinguishable from a complete hash followed by unrelated
# text, so it is only rejoined when the same wrap shape repeats this often in
# the document (tables wrap every row at the same column).
MIN_SHAPE_REPEATS_FOR_VALID_HEAD = 2


# --------------------------------------------------
# FALSE-POSITIVE CONTROLS
# --------------------------------------------------

# File names that look like domains but are not. Extensions that are also
# real TLDs (.zip, .mov, .py, .sh) are deliberately left out.
NON_DOMAIN_EXTENSIONS = (
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".lnk", ".tmp", ".ini", ".log", ".txt",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
)

# Terms that look like domains but are ordinary words or product names in
# reports. Extend this set as you meet recurring false positives.
IGNORED_DOMAINS = frozenset({
    "power.off",
    "asp.net",
    "vb.net",
})

# Words that usually introduce a real network address. A dotted quad that
# follows any other word (for example a product name) may be a version.
NETWORK_CONTEXT_WORDS = frozenset({
    "ip", "ips", "address", "addresses", "server", "servers", "host",
    "hosts", "from", "with", "via", "into", "onto", "connect", "connects",
    "connected", "connecting", "contacted", "contacts", "communicated",
    "communicates", "resolves", "resolved", "dns", "gateway", "proxy",
    "port", "range", "network", "subnet", "domain", "destination",
    "source", "remote", "target", "beacon", "beacons", "callback",
})

# Largest octet at which a dotted quad can still plausibly be a version.
VERSION_LIKE_MAX_OCTET = 99

HASH_TYPES = frozenset({"md5", "sha1", "sha256"})
HASH_LENGTHS = frozenset({32, 40, 64})
HASH_TYPE_BY_LENGTH = {32: "md5", 40: "sha1", 64: "sha256"}


# --------------------------------------------------
# PATTERNS
# --------------------------------------------------

PATTERNS = {
    "cve": re.compile(
        r"\bCVE-\d{4}-\d{4,}\b",
        re.IGNORECASE,
    ),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "attack_technique": re.compile(
        r"\bT\d{4}(?:\.\d{3})?\b"
    ),
    "url": re.compile(
        r"https?://[^\s<>\"']+",
        re.IGNORECASE,
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}\b"
    ),
    # The lookarounds reject a dotted quad that sits inside a longer dotted
    # string (2.1.1.3.0), follows a word character (v1.1.3.0,
    # Grixba_1.1.3.0.exe) or continues with more digits (1.2.3.4.5).
    "ip": re.compile(
        r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)"
    ),
}

TECHNIQUE_ID = PATTERNS["attack_technique"]

# A dotted quad right after a word like "version" or "build" is a version
# number, not a network indicator.
VERSION_CONTEXT = re.compile(
    r"\b(?:v|ver|version|build|release|rev|revision)\.?[\s:=|\-\u2013]*$",
    re.IGNORECASE,
)

# A version label somewhere earlier on the same line makes a dotted quad
# suspicious, but not certain enough to discard it.
NEAR_VERSION_LABEL = re.compile(
    r"\b(?:version|ver|release|revision|build)\b",
    re.IGNORECASE,
)

LAST_WORD = re.compile(r"([A-Za-z][A-Za-z0-9\-]{2,})[\s:|]*$")

# Two hex runs on consecutive lines: a hash that the PDF wrapped.
WRAPPED_HASH = re.compile(
    r"(?<![A-Za-z0-9])([a-fA-F0-9]{4,63})[ \t]*\r?\n[ \t]*([a-fA-F0-9]{4,63})"
    r"(?![A-Za-z0-9])"
)

# Reports often "defang" indicators so they cannot be clicked by accident.
# These rules restore the normal form before matching.
REFANG_RULES = (
    (re.compile(r"\bhxxp(s?)(?=\[?:)", re.IGNORECASE), r"http\1"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[@\]|\[at\]|\(at\)", re.IGNORECASE), "@"),
)


# --------------------------------------------------
# PDF TEXT
# --------------------------------------------------

def extract_pdf_text(pdf_path):
    """Extract text page by page from a text-based PDF."""
    path = Path(pdf_path)

    if not path.is_file():
        raise ValueError("PDF file was not found.")

    if path.stat().st_size > MAX_PDF_BYTES:
        raise ValueError("PDF exceeds the 15 MB size limit.")

    try:
        reader = PdfReader(str(path), strict=True)

        if reader.is_encrypted:
            raise ValueError("Encrypted PDFs are not supported.")

        if len(reader.pages) > MAX_PAGES:
            raise ValueError("PDF exceeds the 100-page limit.")

        pages = []
        total_characters = 0

        for page_number, page in enumerate(reader.pages, start=1):
            text = page.extract_text() or ""
            total_characters += len(text)

            if total_characters > MAX_EXTRACTED_CHARACTERS:
                raise ValueError(
                    "Extracted PDF text exceeds the size limit."
                )

            pages.append({
                "page": page_number,
                "text": text,
            })

        return pages

    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(
            "Unable to read this PDF. It may be damaged or unsupported."
        ) from exc


# --------------------------------------------------
# NORMALIZATION HELPERS
# --------------------------------------------------

def refang(text):
    """Restore defanged indicators such as hxxp:// and example[.]com."""
    for rule, replacement in REFANG_RULES:
        text = rule.sub(replacement, text)
    return text


def refang_pages(pages):
    """Return (restored pages, number of pages that were changed)."""
    restored = []
    changed = 0

    for page in pages:
        text = refang(page["text"])

        if text != page["text"]:
            changed += 1

        restored.append({"page": page["page"], "text": text})

    return restored, changed


def normalize_value(indicator_type, value):
    """Return the canonical form used for output and de-duplication."""
    if indicator_type == "cve":
        return value.upper()

    if indicator_type in HASH_TYPES or indicator_type == "domain":
        return value.lower()

    return value


def is_plausible_hash(value):
    """Reject all-digit strings and trivial patterns such as 000...0."""
    return not value.isdigit() and len(set(value.lower())) > 2


def ip_scope(address):
    """Classify an IPv4 address so reviewers can spot non-routable ones."""
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_private:
        return "private"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified or address.is_reserved:
        return "reserved"
    return "public"


# --------------------------------------------------
# WRAPPED HASH REPAIR
# --------------------------------------------------

def _is_mixed_hex(fragment):
    """True if the fragment holds both a digit and a letter (a-f)."""
    return (
        any(ch.isdigit() for ch in fragment)
        and any(ch.isalpha() for ch in fragment)
    )


def _hash_fragments(match):
    """
    Return (head, tail) if two hex runs could be one wrapped hash.

    All of these must hold: the pieces add up to a hash length, the tail is
    not itself a complete hash, both pieces look like hash fragments (they
    mix digits and letters, so ordinary words such as "deadbeef" and plain
    numbers or dates are rejected), and the joined value is plausible.
    """
    head, tail = match.group(1), match.group(2)

    if len(tail) in HASH_LENGTHS:
        return None

    if len(head) + len(tail) not in HASH_LENGTHS:
        return None

    if not (_is_mixed_hex(head) and _is_mixed_hex(tail)):
        return None

    if not is_plausible_hash(head + tail):
        return None

    return head, tail


def repair_wrapped_hashes_detailed(pages):
    """
    Rejoin hashes that the PDF wrapped across two lines.

    Returns (pages, pages changed, set of rejoined values in lower case).
    """
    # Pass 1: count wrap shapes whose first piece is a valid hash length.
    shapes = Counter()

    for page in pages:
        for match in WRAPPED_HASH.finditer(page["text"]):
            parts = _hash_fragments(match)

            if parts and len(parts[0]) in HASH_LENGTHS:
                shapes[(len(parts[0]), len(parts[1]))] += 1

    rejoined = set()

    def join(match):
        parts = _hash_fragments(match)

        if not parts:
            return match.group(0)

        head, tail = parts

        if (
            len(head) in HASH_LENGTHS
            and shapes[(len(head), len(tail))] < MIN_SHAPE_REPEATS_FOR_VALID_HEAD
        ):
            return match.group(0)

        merged = head + tail
        rejoined.add(merged.lower())
        return merged

    # Pass 2: rewrite only the pairs that passed every check.
    restored = []
    changed = 0

    for page in pages:
        text = WRAPPED_HASH.sub(join, page["text"])

        if text != page["text"]:
            changed += 1

        restored.append({"page": page["page"], "text": text})

    return restored, changed, rejoined


def repair_wrapped_hashes(pages):
    """Return (pages with wrapped hashes rejoined, pages that changed)."""
    restored, changed, _ = repair_wrapped_hashes_detailed(pages)
    return restored, changed


# --------------------------------------------------
# IP CONTEXT
# --------------------------------------------------

def classify_ip_context(page_text, start, end, largest_octet, last_octet=None):
    """
    Judge a dotted quad from its surrounding text.

    Returns "drop" when it is almost certainly not an address (a file name
    or a value right after a version label), "possible_version" when it may
    be a version number and a reviewer should look, or None.
    """
    line_start = page_text.rfind("\n", 0, start) + 1
    before = page_text[line_start:start]
    after = page_text[end:end + 6].lower()

    # 1.1.3.0.exe is a file name.
    if after.startswith(NON_DOMAIN_EXTENSIONS):
        return "drop"

    # "version 1.1.3.0", "v 1.1.3.0", "Build: 1.1.3.0".
    if VERSION_CONTEXT.search(before[-20:]):
        return "drop"

    # A version label earlier on the same line.
    if NEAR_VERSION_LABEL.search(before[-40:]):
        return "possible_version"

    # "Grixba 1.1.3.0": a name that does not introduce an address, followed
    # by small numbers that end in .0 (a build or release number). Requiring
    # the trailing .0 keeps ordinary addresses such as 8.8.8.8 or 1.1.1.1
    # classified by their real scope when any other word precedes them.
    word = LAST_WORD.search(before)

    if (
        word
        and word.group(1).lower() not in NETWORK_CONTEXT_WORDS
        and largest_octet <= VERSION_LIKE_MAX_OCTET
        and last_octet == 0
    ):
        return "possible_version"

    return None


# --------------------------------------------------
# EVIDENCE
# --------------------------------------------------

def attack_evidence(page_text, start, end):
    """
    Return a concise excerpt for an ATT&CK technique ID.

    The excerpt comes from the line holding the ID. If several IDs share a
    line (a table row extracted flat), it runs from this ID to the next one
    so rows do not bleed together; an ID list such as "T1059, T1486" falls
    back to the whole line. If the text is very short and no other ID
    follows on the line, it borrows up to MAX_ATTACK_EXTRA_LINES following
    lines, but never crosses into a line that holds another technique ID.
    """
    line_start = page_text.rfind("\n", 0, start) + 1
    line_end = page_text.find("\n", end)

    if line_end == -1:
        line_end = len(page_text)

    line = page_text[line_start:line_end]
    value = page_text[start:end]
    rel_start = start - line_start
    rel_end = end - line_start

    others = [
        match.span()
        for match in TECHNIQUE_ID.finditer(line)
        if match.start() != rel_start
    ]
    earlier = any(span[1] <= rel_start for span in others)
    later = [span for span in others if span[0] >= rel_end]

    segment_start = rel_start if earlier else 0
    segment_end = later[0][0] if later else len(line)
    segment = line[segment_start:segment_end]

    meaningful = len(
        re.sub(r"[\W_]+", "", segment.replace(value, "", 1))
    ) >= MIN_ATTACK_SEGMENT_CHARS

    if (later or earlier) and not meaningful:
        parts = [line]
    else:
        parts = [segment]

        if not later:
            cursor = line_end + 1
            extra = 0

            while (
                len(" ".join(parts)) < MIN_ATTACK_EVIDENCE_CHARS
                and extra < MAX_ATTACK_EXTRA_LINES
                and cursor < len(page_text)
            ):
                next_end = page_text.find("\n", cursor)

                if next_end == -1:
                    next_end = len(page_text)

                next_line = page_text[cursor:next_end].strip()
                cursor = next_end + 1

                if not next_line:
                    continue

                if TECHNIQUE_ID.search(next_line):
                    break

                parts.append(next_line)
                extra += 1

    evidence = " ".join(" ".join(parts).split())

    if len(evidence) > MAX_ATTACK_EVIDENCE_CHARS:
        center = max(evidence.find(value), 0)
        window_start = max(0, center - MAX_ATTACK_EVIDENCE_CHARS // 2)
        evidence = evidence[
            window_start:window_start + MAX_ATTACK_EVIDENCE_CHARS
        ]

    return evidence


def generic_evidence(page_text, start, end):
    """Return a short window of source text around a finding."""
    window_start = max(0, start - EVIDENCE_RADIUS)
    window_end = min(len(page_text), end + EVIDENCE_RADIUS)
    return " ".join(page_text[window_start:window_end].split())


# --------------------------------------------------
# HASH TABLE ROWS
# --------------------------------------------------

FILENAME_STEM = re.compile(r"[\w$~\-]+(?:\.[\w$~\-]+)*")
HEX_ONLY = re.compile(r"[a-fA-F0-9]+")

# Limits for text that continues on lines below a hash (vertical tables).
# Table cells wrap narrowly, so one description can span many short lines.
MAX_ROW_CONTINUATION_LINES = 12
MAX_CONTINUATION_LINE_CHARS = 70
MAX_ROW_DESCRIPTION_CHARS = 200
# A filename cell is looked for in the first few lines of a block.
FILENAME_SEARCH_LINES = 3
FILENAME_EDGE_CHARS = " ,;:\"'()[]"

# Continuation lines stop as soon as one of these heading-like phrases
# appears. They mark the start of unrelated document content (a new
# section, a page footer, or a table header), so they must not be
# appended to a hash description.
HASH_CONTEXT_BOUNDARY_PHRASES = (
    "mitre att&ck tactics and techniques",
    "see table 3 through table 11",
    "table 3. play att&ck techniques",
    "end update",
    "update june ",
    "tlp:clear",
    "fbi | cisa | acsc",
    "page ",
)


def _looks_like_filename(token):
    """True for tokens such as SVCHost.dll; false for versions like 1.2."""
    stem, _, extension = token.rpartition(".")

    return (
        bool(stem)
        and FILENAME_STEM.fullmatch(stem) is not None
        and 1 <= len(extension) <= 5
        and extension.isalnum()
        and not extension.isdigit()
    )


def _is_hash_context_boundary(line):
    """Return True when a line marks the start of unrelated document content.

    Used to stop accumulating continuation lines into a hash description
    when a known section heading, page footer, or table header begins.
    """
    normalized = " ".join(line.lower().split())
    return any(
        normalized.startswith(phrase)
        for phrase in HASH_CONTEXT_BOUNDARY_PHRASES
    )


def associate_hashes_with_table_rows(text):
    """
    Link hashes to the filename and description that belong to them.

    Each complete, plausible hash starts a block. The block takes the text
    after the hash on the same line and then the short lines below it
    (tables extracted vertically put each cell on its own line). A block
    ends at the next hash that carries its own text, a blank line, a line
    longer than MAX_CONTINUATION_LINE_CHARS (most likely ordinary prose),
    a recognised section heading (see HASH_CONTEXT_BOUNDARY_PHRASES), or
    after MAX_ROW_CONTINUATION_LINES lines, in which case "truncated" is
    True.

    Hashes listed one after another with no text between them are treated
    as a group that shares the text which follows (a table cell holding
    several hashes for one file). That is an inference from text order, so
    those rows are labelled "shared_following".

    The filename is the first word after a hash on its own line, or a line
    among the first FILENAME_SEARCH_LINES lines of the block that is a
    single word that looks like a file name. A filename is never taken from
    inside a longer sentence. Everything else becomes the description,
    capped at MAX_ROW_DESCRIPTION_CHARS.

    Each result is a dict with type, value (lower case), filename and
    description (None when absent), group_size, truncated, and association:
    "same_line" (text sat on the hash's own line), "following_lines" (text
    came from the lines below), "shared_following" (text came from below a
    group of hashes) or "hash_only" (no text found).

    This is a text-order heuristic, not a table-layout parser, so a
    reviewer should check associations against the source.
    """
    rows = []
    current = None

    def finish(block):
        if block is None:
            return

        texts = list(block["following"])

        if block["same_line"]:
            texts.insert(0, block["same_line"])

        filename = None

        if block["same_line"]:
            pieces = texts[0].split(None, 1)
            candidate = pieces[0].strip(FILENAME_EDGE_CHARS)

            if _looks_like_filename(candidate):
                filename = candidate
                remainder = pieces[1] if len(pieces) > 1 else ""
                texts = ([remainder] if remainder.strip() else []) + texts[1:]

        if filename is None:
            for index in range(min(len(texts), FILENAME_SEARCH_LINES)):
                candidate = texts[index].strip(FILENAME_EDGE_CHARS)

                if (
                    len(texts[index].split()) == 1
                    and _looks_like_filename(candidate)
                ):
                    filename = candidate
                    del texts[index]
                    break

        description = " ".join(" ".join(texts).split())
        description = description[:MAX_ROW_DESCRIPTION_CHARS].rstrip()
        group_size = len(block["hashes"])

        if not block["same_line"] and not block["following"]:
            association = "hash_only"
        elif block["same_line"]:
            association = "same_line"
        elif group_size > 1:
            association = "shared_following"
        else:
            association = "following_lines"

        for entry in block["hashes"]:
            rows.append({
                "type": entry["type"],
                "value": entry["value"],
                "filename": filename,
                "description": description or None,
                "association": association,
                "group_size": group_size,
                "truncated": block["truncated"],
            })

    for line in text.splitlines():
        stripped = line.strip()

        if not stripped:
            finish(current)
            current = None
            continue

        parts = stripped.split(None, 1)
        token = parts[0]

        if (
            len(token) in HASH_LENGTHS
            and HEX_ONLY.fullmatch(token) is not None
            and is_plausible_hash(token)
        ):
            entry = {
                "type": HASH_TYPE_BY_LENGTH[len(token)],
                "value": token.lower(),
            }
            same_line = parts[1].strip() if len(parts) > 1 else ""

            if (
                current is not None
                and not same_line
                and not current["same_line"]
                and not current["following"]
            ):
                # A bare hash straight after another bare hash: same group.
                current["hashes"].append(entry)
            else:
                finish(current)
                current = {
                    "hashes": [entry],
                    "same_line": same_line,
                    "following": [],
                    "truncated": False,
                }
        elif current is not None:
            if _is_hash_context_boundary(stripped):
                finish(current)
                current = None
            elif len(current["following"]) >= MAX_ROW_CONTINUATION_LINES:
                current["truncated"] = True
                finish(current)
                current = None
            elif len(stripped) > MAX_CONTINUATION_LINE_CHARS:
                finish(current)
                current = None
            else:
                current["following"].append(stripped)

    finish(current)
    return rows


def build_hash_context(pages):
    """
    Map (page number, hash value) to table context found on that page.

    Only rows that carry a filename or a description are kept; a hash with
    no nearby text gets no entry. The first row seen for a hash on a page
    wins.
    """
    context = {}

    for page in pages:
        for row in associate_hashes_with_table_rows(page["text"]):
            if not (row["filename"] or row["description"]):
                continue

            context.setdefault((page["page"], row["value"]), {
                "filename": row["filename"],
                "description": row["description"],
                "association": row["association"],
                "group_size": row["group_size"],
                "truncated": row["truncated"],
            })

    return context


def attach_hash_context(findings, context):
    """Add a "context" dict to hash findings that have table text nearby."""
    for finding in findings:
        if finding["type"] not in HASH_TYPES:
            continue

        found = context.get((finding["page"], finding["value"]))

        if found:
            finding["context"] = dict(found)

    return findings


# --------------------------------------------------
# DETECTION
# --------------------------------------------------

def detect_indicators(pages, enabled_types=None, rejoined_hashes=None):
    """
    Detect candidate CTI indicators and retain page-level evidence.

    enabled_types limits detection to a subset of PATTERNS keys, for
    example {"cve", "sha256", "url"}. The default is every type.

    rejoined_hashes is an optional set of lower-case hash values that were
    rebuilt from wrapped lines; those findings get a distinct method so a
    reviewer knows to check them against the source.
    """
    active_types = set(enabled_types) if enabled_types else set(PATTERNS)
    rejoined = rejoined_hashes or frozenset()
    findings = []
    seen = set()

    for page_data in pages:
        page_number = page_data["page"]
        page_text = page_data["text"]
        page_findings = []

        # Record URL ranges so domains inside URLs are not duplicated.
        url_ranges = [
            match.span()
            for match in PATTERNS["url"].finditer(page_text)
        ]

        for indicator_type, pattern in PATTERNS.items():
            if indicator_type not in active_types:
                continue

            for match in pattern.finditer(page_text):
                value = match.group(0).rstrip(TRAILING_PUNCTUATION)
                extra = {}
                method = "regex_rule"

                if indicator_type == "url":
                    if len(value) > MAX_URL_LENGTH:
                        continue

                elif indicator_type == "domain":
                    lowered = value.lower()

                    if len(value) > MAX_DOMAIN_LENGTH:
                        continue

                    # The URL is already reported as a URL finding.
                    if any(
                        start <= match.start() < end
                        for start, end in url_ranges
                    ):
                        continue

                    # Avoid classifying common file names as domains.
                    if lowered.endswith(NON_DOMAIN_EXTENSIONS):
                        continue

                    # Avoid known non-domain terms that look like domains.
                    if lowered in IGNORED_DOMAINS:
                        continue

                elif indicator_type == "ip":
                    try:
                        address = ipaddress.IPv4Address(value)
                    except ipaddress.AddressValueError:
                        continue

                    verdict = classify_ip_context(
                        page_text,
                        match.start(),
                        match.end(),
                        max(address.packed),
                        address.packed[-1],
                    )

                    if verdict == "drop":
                        continue

                    scope = ip_scope(address)

                    # Only a public address is re-labelled; a private or
                    # reserved scope stays visible to the reviewer.
                    if verdict == "possible_version" and scope == "public":
                        scope = "possible_version"

                    extra["ip_scope"] = scope

                elif indicator_type in HASH_TYPES:
                    if not is_plausible_hash(value):
                        continue

                value = normalize_value(indicator_type, value)

                if indicator_type in HASH_TYPES and value in rejoined:
                    method = "regex_rule_rejoined"

                # Case-insensitive types are already normalized above, so
                # URL paths keep their case and stay distinct.
                key = (indicator_type, value, page_number)

                if key in seen:
                    continue

                seen.add(key)

                # Keep a short source excerpt around the finding.
                if indicator_type == "attack_technique":
                    evidence = attack_evidence(
                        page_text, match.start(), match.end()
                    )
                else:
                    evidence = generic_evidence(
                        page_text, match.start(), match.end()
                    )

                page_findings.append((
                    match.start(),
                    {
                        "type": indicator_type,
                        "value": value,
                        "page": page_number,
                        "evidence": evidence,
                        "method": method,
                        "review_status": "unreviewed",
                        **extra,
                    },
                ))

        # Report findings in reading order within each page.
        page_findings.sort(key=lambda item: item[0])

        remaining = MAX_FINDINGS - len(findings)
        findings.extend(item[1] for item in page_findings[:remaining])

        if len(findings) >= MAX_FINDINGS:
            break

    return findings


def group_indicators(findings):
    """
    Merge repeated findings into one entry per unique indicator.

    Case-insensitive types (CVEs, hashes, domains) are merged regardless
    of case; URLs and other values are matched exactly. Each group lists
    every page where the indicator appears, how many times it occurs, and
    up to MAX_EVIDENCE_PER_GROUP evidence excerpts. Groups keep the order
    in which their indicator was first seen.
    """
    groups = {}

    for item in findings:
        indicator_type = item.get("type")
        raw_value = item.get("value")

        if not indicator_type or not raw_value:
            continue

        value = normalize_value(indicator_type, str(raw_value).strip())
        key = (indicator_type, value)
        group = groups.get(key)

        if group is None:
            group = {
                "type": indicator_type,
                "value": value,
                "pages": [],
                "occurrences": 0,
                "evidence": [],
                "method": item.get("method", "regex_rule"),
                "review_status": item.get("review_status", "unreviewed"),
            }

            if "ip_scope" in item:
                group["ip_scope"] = item["ip_scope"]

            groups[key] = group

        group["occurrences"] += 1

        # Keep the first table context seen for this indicator.
        if "context" in item and "context" not in group:
            group["context"] = dict(item["context"])

        page = item.get("page")

        if page is not None and page not in group["pages"]:
            group["pages"].append(page)

        if len(group["evidence"]) < MAX_EVIDENCE_PER_GROUP:
            group["evidence"].append({
                "page": page,
                "evidence": item.get("evidence", ""),
            })

    result = list(groups.values())

    for group in result:
        group["pages"].sort()

    return result


# --------------------------------------------------
# PUBLIC ENTRY POINT
# --------------------------------------------------

def extract_cti_from_pdf(pdf_path, enabled_types=None):
    """Return extracted text statistics and candidate indicators."""
    pages = extract_pdf_text(pdf_path)
    pages, defanged_pages = refang_pages(pages)

    if REPAIR_WRAPPED_HASHES:
        pages, rejoined_pages, rejoined_values = (
            repair_wrapped_hashes_detailed(pages)
        )
    else:
        rejoined_pages, rejoined_values = 0, set()

    findings = detect_indicators(pages, enabled_types, rejoined_values)
    attach_hash_context(findings, build_hash_context(pages))

    limitations = [
        "Findings are candidates and require human review.",
        "Scanned pages may require OCR.",
        "Regex detection does not establish maliciousness.",
        "ATT&CK identifiers are not validated against the ATT&CK catalog.",
        "Hash types are inferred from length only.",
    ]

    if defanged_pages:
        limitations.append(
            f"Defanged indicators on {defanged_pages} page(s) were "
            "restored before matching; evidence shows the restored text."
        )

    if rejoined_pages:
        limitations.append(
            f"Hashes split across lines on {rejoined_pages} page(s) were "
            "rejoined before matching; verify them against the source."
        )

    scopes = {
        item.get("ip_scope") for item in findings if item["type"] == "ip"
    }

    if "possible_version" in scopes:
        limitations.append(
            "Some IP-like values may be version numbers (marked possible "
            "version); confirm them in the source before use."
        )

    if scopes - {None, "public", "possible_version"}:
        limitations.append(
            "Some IP addresses are private or reserved and may not be "
            "useful as shared indicators."
        )

    contexts = [item["context"] for item in findings if "context" in item]

    if contexts:
        limitations.append(
            "Filenames and descriptions beside hashes are inferred from the "
            "order of text in the PDF and may be mismatched; check them "
            "against the source."
        )

    if any(ctx["truncated"] for ctx in contexts):
        limitations.append(
            "Some hash descriptions were cut at the line limit and may be "
            "incomplete."
        )

    if len(findings) >= MAX_FINDINGS:
        limitations.append(
            f"Results were limited to the first {MAX_FINDINGS} findings."
        )

    return {
        "page_count": len(pages),
        "pages_with_text": sum(
            1 for page in pages if page["text"].strip()
        ),
        "defanged_pages": defanged_pages,
        "summary": dict(Counter(item["type"] for item in findings)),
        "findings": findings,
        "grouped_findings": group_indicators(findings),
        "limitations": limitations,
    }