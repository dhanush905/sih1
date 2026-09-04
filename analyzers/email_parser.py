"""Robust .eml email parser built on the standard-library `email` package."""
from __future__ import annotations

import email
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.message import Message
from typing import Any

from bs4 import BeautifulSoup


@dataclass
class Attachment:
    """Metadata for an email attachment."""

    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str
    payload: bytes = b""


@dataclass
class ParsedEmail:
    """Structured representation of a parsed email."""

    from_: str = ""
    to: str = ""
    cc: str = ""
    subject: str = ""
    date: str = ""
    message_id: str = ""
    reply_to: str = ""
    return_path: str = ""
    mime_type: str = ""
    content_type: str = ""
    body_text: str = ""
    body_html: str = ""
    received_headers: list[str] = field(default_factory=list)
    auth_headers: dict[str, str] = field(default_factory=dict)
    urls: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)
    all_ips: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dict representation (attachments without payload)."""
        return {
            "from": self.from_,
            "to": self.to,
            "cc": self.cc,
            "subject": self.subject,
            "date": self.date,
            "message_id": self.message_id,
            "reply_to": self.reply_to,
            "return_path": self.return_path,
            "mime_type": self.mime_type,
            "content_type": self.content_type,
            "body_text": self.body_text,
            "body_html": self.body_html,
            "received_headers": [str(h) for h in self.received_headers],
            "auth_headers": {str(k): str(v) for k, v in self.auth_headers.items()},
            "urls": self.urls,
            "attachments": [
                {
                    "filename": a.filename,
                    "content_type": a.content_type,
                    "size": a.size,
                    "sha256": a.sha256,
                    "md5": a.md5,
                }
                for a in self.attachments
            ],
            "raw_headers": self.raw_headers,
            "all_ips": self.all_ips,
        }


_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_email(raw: bytes | str) -> ParsedEmail:
    """Parse raw email bytes/string into a :class:`ParsedEmail`.

    Never raises on malformed input; returns a best-effort object.
    """
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8", errors="replace")
    else:
        raw_bytes = raw

    parsed = ParsedEmail()
    try:
        msg: Message = email.message_from_bytes(raw_bytes, policy=policy.default)
    except Exception:
        # last-resort: try without default policy
        try:
            msg = email.message_from_bytes(raw_bytes)
        except Exception:
            return parsed

    try:
        parsed.from_ = _hdr(msg, "From")
        parsed.to = _hdr(msg, "To")
        parsed.cc = _hdr(msg, "Cc")
        parsed.subject = _hdr(msg, "Subject")
        parsed.date = _hdr(msg, "Date")
        parsed.message_id = _hdr(msg, "Message-ID")
        parsed.reply_to = _hdr(msg, "Reply-To")
        parsed.return_path = _hdr(msg, "Return-Path")
        parsed.mime_type = _hdr(msg, "MIME-Version", "")
        parsed.content_type = msg.get_content_type() or ""
    except Exception:
        pass

    # received headers — convert to plain strings
    try:
        raw_received = msg.get_all("Received") or []
        parsed.received_headers = [str(h) for h in raw_received]
    except Exception:
        parsed.received_headers = []

    # authentication headers
    auth = {}
    for hname in ("Authentication-Results", "Received-SPF", "DKIM-Signature",
                  "DMARC-Authentication-Results", "ARC-Authentication-Results"):
        try:
            vals = msg.get_all(hname)
            if vals:
                auth[hname] = " | ".join(str(v) for v in vals)
        except Exception:
            pass
    parsed.auth_headers = auth

    # raw headers (string map)
    try:
        for k, v in msg.items():
            parsed.raw_headers.setdefault(str(k), str(v))
    except Exception:
        pass

    # body extraction
    body_text, body_html, attachments = _extract_body_and_attachments(msg)
    parsed.body_text = body_text
    parsed.body_html = body_html
    parsed.attachments = attachments

    # URLs from text + html
    urls = set()
    for u in _URL_RE.findall(body_text or ""):
        urls.add(u.rstrip(".,);]>\"'"))
    for u in _extract_html_urls(body_html or ""):
        urls.add(u)
    parsed.urls = sorted(urls)

    # all IPs
    ips = set()
    for rh in parsed.received_headers:
        ips.update(_IP_RE.findall(rh))
    ips.update(_IP_RE.findall(body_text or ""))
    ips.update(_IP_RE.findall(body_html or ""))
    for u in parsed.urls:
        m = re.search(r"https?://(\d{1,3}(?:\.\d{1,3}){3})", u)
        if m:
            ips.add(m.group(1))
    parsed.all_ips = sorted({ip for ip in ips if _is_valid_ip(ip)})

    return parsed


def _hdr(msg: Message, name: str, default: str = "") -> str:
    try:
        v = msg.get(name)
        return str(v) if v is not None else default
    except Exception:
        return default


def _extract_body_and_attachments(msg: Message) -> tuple[str, str, list[Attachment]]:
    """Walk a (possibly multipart) message and return text, html, attachments."""
    body_text = ""
    body_html = ""
    attachments: list[Attachment] = []

    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.is_multipart():
                    continue
                ctype = part.get_content_type() or ""
                disp = part.get_content_disposition() or ""
                try:
                    payload = part.get_payload(decode=True)
                except Exception:
                    payload = None
                if payload is None:
                    continue
                if "attachment" in disp or part.get_filename():
                    attachments.append(_make_attachment(part, payload))
                elif ctype == "text/plain" and not body_text:
                    body_text = _decode_bytes(payload, part)
                elif ctype == "text/html" and not body_html:
                    body_html = _decode_bytes(payload, part)
                elif ctype.startswith("text/") and not body_text:
                    body_text = _decode_bytes(payload, part)
        else:
            try:
                payload = msg.get_payload(decode=True)
            except Exception:
                payload = None
            if payload is not None:
                ctype = msg.get_content_type() or ""
                if ctype == "text/html":
                    body_html = _decode_bytes(payload, msg)
                else:
                    body_text = _decode_bytes(payload, msg)
    except Exception:
        pass

    return body_text, body_html, attachments


def _decode_bytes(payload: bytes, part: Message) -> str:
    """Decode bytes to string respecting charset hints."""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, TypeError):
        return payload.decode("utf-8", errors="replace")


def _make_attachment(part: Message, payload: bytes) -> Attachment:
    """Build an :class:`Attachment` from a message part."""
    fname = part.get_filename() or "unknown"
    ctype = part.get_content_type() or "application/octet-stream"
    size = len(payload)
    sha = hashlib.sha256(payload).hexdigest()
    md5 = hashlib.md5(payload).hexdigest()
    return Attachment(
        filename=fname,
        content_type=ctype,
        size=size,
        sha256=sha,
        md5=md5,
        payload=payload,
    )


def _extract_html_urls(html: str) -> list[str]:
    """Extract href URLs from HTML anchor tags."""
    urls: list[str] = []
    if not html:
        return urls
    try:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("http"):
                urls.append(href)
    except Exception:
        pass
    return urls


def _is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
