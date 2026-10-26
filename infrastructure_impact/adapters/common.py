"""Shared source expressions and normalized-record builders."""

import hashlib
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
# Format adapters have a package-wide fingerprint; parser changes remain distinct from source changes.
ADAPTER_VERSION = hashlib.sha256(
    b"".join(p.read_bytes() for p in sorted(Path(__file__).parent.glob("*.py")))
).hexdigest()[:16]


def cves(text):
    return sorted({x.upper() for x in CVE.findall(text)})


def iso_date(value):
    if not value:
        return None
    value = re.sub(r"(\d)\s*(?:st|nd|rd|th)\b", r"\1", value.strip())
    for fmt in (
        "%B %d %Y",
        "%b %d %Y",
        "%b %d, %Y",
        "%B %d, %Y",
        "%B %dth, %Y",
        "%B %dst, %Y",
        "%B %dnd, %Y",
        "%B %drd, %Y",
    ):
        try:
            return datetime.strptime(value.strip(), fmt).date().isoformat()
        except ValueError:
            pass
    return value


def availability(details, category, date=None):
    if category == "no_fix_planned":
        return "no_fix_planned"
    if category == "none_available":
        return "unavailable"
    if category != "vendor_fix":
        return "not_a_fix"
    if re.search(
        r"\b(partially mitigate|partial mitigation|partial fix|not fully fixed)\b", details, re.I
    ):
        return "partial_mitigation"
    month = re.search(r"\b([A-Z][a-z]{2,8})\s+(20\d{2})\b", details)
    if month:
        for fmt in ("%b %Y", "%B %Y"):
            try:
                if (
                    datetime.strptime(month.group(0), fmt).date()
                    > datetime.now(timezone.utc).date()
                ):
                    return "planned"
            except ValueError:
                pass
    if date:
        try:
            if (
                datetime.fromisoformat(date.replace("Z", "+00:00")).date()
                > datetime.now(timezone.utc).date()
            ):
                return "planned"
        except ValueError:
            pass
    if re.search(r"\b(ETA|TBD|upcoming|scheduled|will be|future release)\b", details, re.I):
        return "planned"
    return "vendor_reports_fixed"


def base(vendor, url, advisory_id, title, published=None, updated=None):
    return {
        "schema_version": 2,
        "vendor": vendor,
        "advisory_id": advisory_id,
        "title": title,
        "adapter_version": ADAPTER_VERSION,
        "source_url": url,
        "source_format": "application/json",
        "published_at": published,
        "updated_at": updated,
        "document_status": "unknown",
        "cves": [],
        "assessments": [],
        "notes": [],
        "metrics": [],
        "timeline": [],
        "warnings": [],
    }


def assessment(
    cid, product, status, locator, versions=None, remediations=None, scope="cve_specific"
):
    return {
        "cve_id": cid,
        "product_id": product,
        "product": product,
        "status": status,
        "source_statuses": [status],
        "scope": scope,
        "versions": versions or [],
        "remediations": remediations or [],
        "exposure": [],
        "product_context": [],
        "evidence_locator": locator,
    }


class Node:
    def __init__(self, tag="", attrs=None):
        self.tag, self.attrs, self.children = tag, dict(attrs or []), []
        self.parent = None

    def text(self):
        return " ".join(
            " ".join(c.text() if isinstance(c, Node) else c for c in self.children).split()
        )

    def find(self, tags):
        for c in self.children:
            if isinstance(c, Node):
                if c.tag in tags:
                    yield c
                yield from c.find(tags)


class HTML(HTMLParser):
    def __init__(self, raw):
        super().__init__(convert_charrefs=True)
        self.root = Node("root")
        self.stack = [self.root]
        self.feed(raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw)

    def handle_starttag(self, tag, attrs):
        n = Node(tag, attrs)
        n.parent = self.stack[-1]
        self.stack[-1].children.append(n)
        if tag not in {
            "area",
            "base",
            "br",
            "col",
            "embed",
            "hr",
            "img",
            "input",
            "link",
            "meta",
            "param",
            "source",
            "track",
            "wbr",
        }:
            self.stack.append(n)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                self.stack = self.stack[:i]
                break

    def handle_data(self, text):
        if self.stack[-1].tag not in {"script", "style"}:
            self.stack[-1].children.append(text)


def pdf_text(raw, layout=False):
    import shutil
    import subprocess
    import tempfile

    executable = shutil.which("pdftotext")
    if not executable:
        # launchd's minimal PATH does not include Homebrew by default.
        executable = next(
            (
                p
                for p in ("/opt/homebrew/bin/pdftotext", "/usr/local/bin/pdftotext")
                if Path(p).is_file()
            ),
            None,
        )
    if not executable:
        raise ValueError("PDF collection requires Poppler pdftotext")
    with tempfile.NamedTemporaryFile(suffix=".pdf") as f:
        f.write(raw)
        f.flush()
        return subprocess.run(
            [executable, "-layout" if layout else "-raw", f.name, "-"],
            check=True,
            capture_output=True,
            timeout=30,
        ).stdout.decode()
