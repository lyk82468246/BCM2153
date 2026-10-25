#!/usr/bin/env python3
"""Read bounded ZIP widget metadata and HTML references without extracting or executing."""

from __future__ import annotations

import argparse
import hashlib
from html.parser import HTMLParser
import io
import json
from pathlib import Path
import posixpath
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET
import zipfile
import zlib


class WidgetError(ValueError):
    pass


MAX_ARCHIVE = 8 * 1024 * 1024
MAX_MEMBER = 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_MEMBERS = 512
NS = "{http://www.w3.org/ns/widgets}"


def canonical_member(name: str) -> bool:
    return bool(name) and not (
        name.startswith("/") or "\\" in name or "\0" in name
        or any(part in ("", ".", "..") for part in name.rstrip("/").split("/"))
    )


def reference(base: str, value: str, files: set[str]) -> dict:
    parts = urlsplit(value)
    row = {"value": value}
    if parts.scheme or parts.netloc:
        return {**row, "status": "external"}
    path = unquote(parts.path)
    if "\\" in path or "\0" in path or path.startswith("/"):
        return {**row, "status": "outside-package"}
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(base), path)) if path else base
    if resolved == ".." or resolved.startswith("../"):
        return {**row, "status": "outside-package"}
    return {**row, "path": resolved, "status": "present" if resolved in files else "missing"}


class EntryHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.references = []
        self.events = []
        self.base_elements = []

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if value is None:
                continue
            if tag == "base" and key == "href":
                self.base_elements.append(value)
            elif key in ("src", "href"):
                self.references.append({"tag": tag, "attribute": key, "line": self.getpos()[0], "value": value})
            elif key.startswith("on"):
                self.events.append({"tag": tag, "attribute": key, "line": self.getpos()[0], "value": value})

    handle_startendtag = handle_starttag


def probe(path: Path) -> dict:
    # One bounded snapshot: no file reopening after hash/size validation.
    with path.open("rb") as stream:
        packed = stream.read(MAX_ARCHIVE + 1)
    if len(packed) > MAX_ARCHIVE:
        raise WidgetError("archive exceeds byte budget")
    rows, data = [], {}
    try:
        with zipfile.ZipFile(io.BytesIO(packed)) as archive:
            members = archive.infolist()
            if len(members) > MAX_MEMBERS:
                raise WidgetError("member count exceeds budget")
            names = [member.filename for member in members]
            if len(set(names)) != len(names):
                raise WidgetError("duplicate ZIP member name")
            if not all(canonical_member(name) for name in names):
                raise WidgetError("noncanonical ZIP member name")
            if any(member.file_size > MAX_MEMBER for member in members):
                raise WidgetError("member exceeds expanded byte budget")
            if sum(member.file_size for member in members) > MAX_TOTAL:
                raise WidgetError("archive exceeds expanded byte budget")
            for member in members:
                if member.is_dir():
                    if member.file_size:
                        raise WidgetError("directory contains data")
                    continue
                with archive.open(member) as stream:
                    body = stream.read(MAX_MEMBER + 1)
                if len(body) > MAX_MEMBER or len(body) != member.file_size:
                    raise WidgetError("expanded member length mismatch")
                data[member.filename] = body
                rows.append({"path": member.filename, "bytes": len(body),
                             "packed_bytes": member.compress_size,
                             "sha256": hashlib.sha256(body).hexdigest(),
                             "crc32": f"{member.CRC:08x}"})
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, zlib.error) as exc:
        raise WidgetError(f"ZIP validation failed: {exc}") from exc
    if "config.xml" not in data:
        raise WidgetError("root config.xml is absent")
    try:
        xml = data["config.xml"].decode("utf-8-sig")
        if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
            raise WidgetError("XML declarations with entities/DOCTYPE are unsupported")
        root = ET.fromstring(xml)
    except (UnicodeError, ET.ParseError) as exc:
        raise WidgetError(f"manifest parse failed: {exc}") from exc
    if root.tag != NS + "widget":
        raise WidgetError("unsupported widget root/namespace")
    content = root.find(NS + "content")
    if content is None or not content.get("src"):
        raise WidgetError("manifest content src is absent")
    files = set(data)
    entry = reference("config.xml", content.get("src"), files)
    if entry["status"] != "present":
        raise WidgetError(f"manifest entry is {entry['status']}")
    try:
        html = EntryHTML()
        html.feed(data[entry["path"]].decode("utf-8-sig"))
        html.close()
    except (UnicodeError, ValueError) as exc:
        raise WidgetError(f"entry HTML parse failed: {exc}") from exc
    references = []
    for item in html.references:
        resolved = reference(entry["path"], item["value"], files)
        if html.base_elements:
            # A browser's base-element handling needs a separate interpretation.
            resolved = {"value": item["value"], "status": "unresolved-base-element"}
        references.append({**item, **resolved})
    return {
        "input": str(path), "bytes": len(packed), "sha256": hashlib.sha256(packed).hexdigest(),
        "zip_members": len(members), "files": rows, "crc_checked": True,
        "expanded_bytes": sum(len(body) for body in data.values()),
        "manifest": {"attributes": root.attrib,
                     "title": root.findtext(NS + "title"),
                     "access": [element.attrib for element in root.findall(NS + "access")],
                     "entry": entry},
        "html": {"references": references, "event_attributes": html.events,
                 "base_elements": html.base_elements},
        "limitations": ["ZIP CRC and lengths validate the stored package, not firmware authenticity",
                        "HTML attributes are static text; no JavaScript, URLs or event handlers execute",
                        "CSS URLs, dynamic references, native host bindings and installation paths remain unknown"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="New metadata JSON path; never overwritten")
    args = parser.parse_args()
    try:
        report = probe(args.input)
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
    except (OSError, WidgetError, ValueError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(f"Validated {report['zip_members']} ZIP members; metadata: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
