"""IMAP email connector for real-time inbox monitoring.

Provides a secure, session-based IMAP connection with support for Gmail,
Outlook, Yahoo, and any custom IMAP server.
"""
from __future__ import annotations

import email
import imaplib
import ssl
import time
from dataclasses import dataclass, field
from email.header import decode_header
from typing import Optional

# ---------------------------------------------------------------------------
# Provider presets
# ---------------------------------------------------------------------------
PROVIDER_PRESETS: dict[str, dict] = {
    "Gmail": {
        "host": "imap.gmail.com",
        "port": 993,
        "ssl": True,
        "help": (
            "Gmail requires an **App Password** (not your regular password).\n"
            "1. Enable 2-Step Verification at myaccount.google.com/security\n"
            "2. Go to myaccount.google.com/apppasswords\n"
            "3. Generate a password for 'Mail' → paste it below."
        ),
    },
    "Outlook / Hotmail": {
        "host": "outlook.office365.com",
        "port": 993,
        "ssl": True,
        "help": (
            "Use your Outlook email and password.\n"
            "If using MFA, create an App Password at account.microsoft.com/security."
        ),
    },
    "Yahoo Mail": {
        "host": "imap.mail.yahoo.com",
        "port": 993,
        "ssl": True,
        "help": (
            "Yahoo requires an **App Password**.\n"
            "Go to Account Security → Generate App Password → select 'Other App'."
        ),
    },
    "Custom IMAP": {
        "host": "",
        "port": 993,
        "ssl": True,
        "help": "Enter your IMAP server host, port, and credentials below.",
    },
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class EmailSummary:
    """Lightweight summary of a fetched email."""
    uid: str
    subject: str
    sender: str
    date: str
    size_bytes: int
    is_read: bool
    folder: str
    raw_bytes: bytes = field(default=b"", repr=False)

    def to_dict(self) -> dict:
        return {
            "uid": self.uid,
            "subject": self.subject,
            "sender": self.sender,
            "date": self.date,
            "size_bytes": self.size_bytes,
            "is_read": self.is_read,
            "folder": self.folder,
        }


@dataclass
class ConnectionResult:
    """Result of an IMAP connection attempt."""
    success: bool
    message: str
    mailbox_info: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# IMAP Connector
# ---------------------------------------------------------------------------
class IMAPConnector:
    """Manages a persistent IMAP connection with helper methods."""

    def __init__(self, host: str, port: int, username: str, password: str, use_ssl: bool = True):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self._conn: Optional[imaplib.IMAP4_SSL | imaplib.IMAP4] = None

    # ---- Connection ----
    def connect(self) -> ConnectionResult:
        """Establish connection and login. Returns ConnectionResult."""
        try:
            if self.use_ssl:
                ctx = ssl.create_default_context()
                self._conn = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=ctx)
            else:
                self._conn = imaplib.IMAP4(self.host, self.port)

            self._conn.login(self.username, self.password)
            info = self._get_mailbox_info()
            return ConnectionResult(success=True, message="Connected successfully.", mailbox_info=info)

        except imaplib.IMAP4.error as e:
            return ConnectionResult(success=False, message=f"Authentication failed: {e}")
        except ssl.SSLError as e:
            return ConnectionResult(success=False, message=f"SSL error: {e}")
        except OSError as e:
            return ConnectionResult(success=False, message=f"Network error: {e}")
        except Exception as e:
            return ConnectionResult(success=False, message=f"Unexpected error: {e}")

    def disconnect(self) -> None:
        """Cleanly close the IMAP connection."""
        if self._conn:
            try:
                self._conn.logout()
            except Exception:
                pass
            self._conn = None

    def is_connected(self) -> bool:
        """Check if connection is alive."""
        if not self._conn:
            return False
        try:
            self._conn.noop()
            return True
        except Exception:
            return False

    def _get_mailbox_info(self) -> dict:
        """Get basic mailbox statistics."""
        info: dict = {}
        try:
            _, data = self._conn.select("INBOX")
            info["inbox_count"] = int(data[0]) if data and data[0] else 0
            _, unread_data = self._conn.search(None, "UNSEEN")
            unread_ids = unread_data[0].split() if unread_data and unread_data[0] else []
            info["unread_count"] = len(unread_ids)
            _, folders_data = self._conn.list()
            info["folders"] = len(folders_data) if folders_data else 0
        except Exception:
            pass
        return info

    # ---- Fetch Emails ----
    def fetch_emails(
        self,
        folder: str = "INBOX",
        limit: int = 20,
        unread_only: bool = False,
        fetch_raw: bool = False,
    ) -> list[EmailSummary]:
        """Fetch email summaries (and optionally raw bytes) from a folder."""
        if not self._conn:
            return []

        try:
            self._conn.select(folder, readonly=True)
            search_criteria = "UNSEEN" if unread_only else "ALL"
            _, data = self._conn.search(None, search_criteria)
            ids = data[0].split() if data and data[0] else []

            # Take the most recent `limit` emails (last in list = newest)
            ids = ids[-limit:][::-1]

            results: list[EmailSummary] = []
            for uid_bytes in ids:
                uid = uid_bytes.decode()
                try:
                    if fetch_raw:
                        _, msg_data = self._conn.fetch(uid_bytes, "(RFC822)")
                        raw = msg_data[0][1] if msg_data and msg_data[0] else b""
                    else:
                        _, msg_data = self._conn.fetch(uid_bytes, "(RFC822.HEADER RFC822.SIZE FLAGS)")
                        raw = b""

                    # Parse headers
                    if fetch_raw and raw:
                        msg = email.message_from_bytes(raw)
                    else:
                        header_data = msg_data[0][1] if msg_data and msg_data[0] else b""
                        msg = email.message_from_bytes(header_data)

                    subject = _decode_header_field(msg.get("Subject", "(No Subject)"))
                    sender = _decode_header_field(msg.get("From", "Unknown"))
                    date = msg.get("Date", "")

                    # Size
                    size = 0
                    try:
                        size_str = msg_data[0][0].decode() if msg_data and msg_data[0] else ""
                        if "RFC822.SIZE" in size_str:
                            size = int(size_str.split("RFC822.SIZE")[1].split()[0].strip("()"))
                    except Exception:
                        pass

                    # Read flag
                    flags_str = msg_data[0][0].decode() if msg_data and msg_data[0] else ""
                    is_read = "\\Seen" in flags_str

                    results.append(EmailSummary(
                        uid=uid,
                        subject=subject,
                        sender=sender,
                        date=date,
                        size_bytes=size,
                        is_read=is_read,
                        folder=folder,
                        raw_bytes=raw if fetch_raw else b"",
                    ))
                except Exception:
                    continue

            return results

        except Exception:
            return []

    def fetch_email_raw(self, uid: str) -> bytes:
        """Fetch full raw RFC822 bytes for a single email by UID."""
        if not self._conn:
            return b""
        try:
            _, msg_data = self._conn.fetch(uid.encode(), "(RFC822)")
            if msg_data and msg_data[0]:
                return msg_data[0][1]
            return b""
        except Exception:
            return b""

    def get_folder_list(self) -> list[str]:
        """Return list of available folders."""
        if not self._conn:
            return ["INBOX"]
        try:
            _, data = self._conn.list()
            folders = []
            for item in data:
                if item:
                    parts = item.decode().split('"/"')
                    name = parts[-1].strip().strip('"') if parts else ""
                    if name:
                        folders.append(name)
            return folders or ["INBOX"]
        except Exception:
            return ["INBOX"]

    def get_unread_count(self, folder: str = "INBOX") -> int:
        """Return unread email count for a folder."""
        if not self._conn:
            return 0
        try:
            self._conn.select(folder, readonly=True)
            _, data = self._conn.search(None, "UNSEEN")
            return len(data[0].split()) if data and data[0] else 0
        except Exception:
            return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _decode_header_field(value: str) -> str:
    """Safely decode an email header field."""
    if not value:
        return ""
    try:
        parts = decode_header(value)
        decoded = []
        for part, charset in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                decoded.append(str(part))
        return " ".join(decoded)
    except Exception:
        return str(value)


def build_connector(
    provider: str,
    username: str,
    password: str,
    custom_host: str = "",
    custom_port: int = 993,
) -> IMAPConnector:
    """Build an IMAPConnector from a provider preset or custom settings."""
    preset = PROVIDER_PRESETS.get(provider, PROVIDER_PRESETS["Custom IMAP"])
    host = custom_host if provider == "Custom IMAP" else preset["host"]
    port = custom_port if provider == "Custom IMAP" else preset["port"]
    use_ssl = preset["ssl"]
    return IMAPConnector(host=host, port=port, username=username, password=password, use_ssl=use_ssl)
