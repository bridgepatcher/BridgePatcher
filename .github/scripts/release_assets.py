#!/usr/bin/env python3
"""Read the Info.plist of the app a release asset ships, without installing or extracting it.

Used by the typosquat watch to check that the release a copy posts really is the release it
ships (see typosquat_watch.fake_release()). Release assets of copies are untrusted, so nothing
in them is run, extracted to disk or trusted beyond its Info.plist: archives are read as a
stream, every size is capped, and only the standard library is used.

Supported assets:
  .pkg  flat packages (xar), as Build-Project.command builds them: each component's Payload
        (gzip- or pbzx-compressed cpio, odc or newc format) is searched for the app. Read as one
        stream while downloading, never written to disk (our BridgePatcher.pkg is about 1 GB, with
        the app's Info.plist near the end of its payload)
  .zip  a zipped app, downloaded into a private temp dir
Other assets (.dmg, ...) return None: they aren't judged. Either way the whole asset is read and its
SHA-256 checked against the digest GitHub reports for it before its Info.plist is returned.

unpack_pkg() is the one exception to "nothing is extracted": for the malware scan of lookalike
repositories (lookalike_malware.py) it writes a package's files into a private folder, as data only,
so the scanners can read them."""

import functools
import gzip
import hashlib
import lzma
import os
import plistlib
import re
import struct
import tempfile
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
import zlib

# Biggest asset read (our BridgePatcher.pkg is about 1 GB)
MAX_ASSET_BYTES = int(os.environ.get("RELEASE_ASSET_MAX_MB", "2048")) * 1024 * 1024
# Biggest xar table of contents, Info.plist and total unpacked payload that are read
MAX_TOC_BYTES = 16 * 1024 * 1024
MAX_PLIST_BYTES = 1024 * 1024
MAX_UNPACKED_BYTES = 4 * 1024 * 1024 * 1024
CHUNK = 1024 * 1024
# An app's own Info.plist: "<...>/Name.app/Contents/Info.plist", not one inside another bundle
APP_PLIST = re.compile(r"^(?:\./)?(?:[^/]+/)*?([^/]+\.app)/Contents/Info\.plist$")
DOWNLOAD_HOSTS = ("github.com",)


class TooBig(Exception):
    pass


# ---------------------------------------------------------------- download --

class Hashed:
    """A download as a stream of chunks, hashed (SHA-256) and capped at MAX_ASSET_BYTES while read."""

    def __init__(self, url):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in DOWNLOAD_HOSTS:
            raise ValueError(f"not a GitHub download URL: {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "typosquat-watch"})
        self._response = urllib.request.urlopen(req, timeout=60)  # https checked above
        self.digest = hashlib.sha256()
        self.size = 0

    def __iter__(self):
        while True:
            block = self._response.read(CHUNK)
            if not block:
                return
            self.size += len(block)
            if self.size > MAX_ASSET_BYTES:
                raise TooBig(f"bigger than {MAX_ASSET_BYTES // (1024 * 1024)} MB")
            self.digest.update(block)
            yield block

    def verify(self, expected_sha256):
        if expected_sha256 and self.digest.hexdigest() != expected_sha256.lower():
            raise ValueError("SHA-256 doesn't match the digest GitHub reports for the asset")

    def close(self):
        self._response.close()


def download(url, expected_sha256=None):
    """Download a release asset (https://github.com/... only) into a private temp dir. Returns its
    path, or raises (too big, bad URL, checksum mismatch). The caller deletes it (see app_info())."""
    source = Hashed(url)
    folder = tempfile.mkdtemp(prefix="release-asset-")
    path = os.path.join(folder, "asset")
    try:
        with open(path, "wb") as f:
            f.writelines(source)
        source.verify(expected_sha256)
    except BaseException:
        remove(path)
        raise
    finally:
        source.close()
    return path


def remove(path):
    try:
        os.remove(path)
        os.rmdir(os.path.dirname(path))
    except OSError:
        pass


# ------------------------------------------------------------------ stream --

class Stream:
    """Reads from an iterator of byte chunks, with peek(n), read(n) and skip(n)."""

    def __init__(self, chunks):
        self._chunks = iter(chunks)
        self._buf = b""
        self._pos = 0
        self._total = 0

    def _fill(self, n):
        if self._pos and len(self._buf) - self._pos < n:
            self._buf, self._pos = self._buf[self._pos:], 0
        while len(self._buf) - self._pos < n:
            block = next(self._chunks, b"")
            if not block:
                return
            self._total += len(block)
            if self._total > MAX_UNPACKED_BYTES:
                raise TooBig("payload unpacks to too much data")
            self._buf += block

    def consumed(self):
        """Bytes read or skipped so far."""
        return self._total - (len(self._buf) - self._pos)

    def peek(self, n):
        self._fill(n)
        return self._buf[self._pos:self._pos + n]

    def read(self, n):
        out = self.peek(n)
        self._pos += len(out)
        return out

    def skip(self, n):
        while n > 0:
            left = len(self._buf) - self._pos
            if not left:
                self._buf, self._pos = b"", 0
                self._fill(1)
                left = len(self._buf)
                if not left:
                    return
            step = min(n, left)
            self._pos += step
            n -= step


def part(stream, length):
    """The next length bytes of a stream, as chunks."""
    while length > 0:
        block = stream.read(min(CHUNK, length))
        if not block:
            return
        length -= len(block)
        yield block


def inflate(chunks, wbits):
    d = zlib.decompressobj(wbits)
    for block in chunks:
        yield d.decompress(block, CHUNK * 4)
        while d.unconsumed_tail:
            yield d.decompress(d.unconsumed_tail, CHUNK * 4)
        if d.eof:
            return
    yield d.flush()


def pbzx(stream):
    """Chunks of an Apple pbzx stream (xz chunks, or stored ones)."""
    stream.read(12)  # "pbzx" + chunk size
    while True:
        header = stream.read(16)
        if len(header) < 16:
            return
        _flags, length = struct.unpack(">QQ", header)
        if length > MAX_UNPACKED_BYTES:
            raise TooBig("pbzx chunk too big")
        data = stream.read(length)
        yield lzma.decompress(data) if data.startswith(b"\xfd7zXZ\x00") else data


def payload_stream(raw):
    """The cpio stream of a component's Payload (raw: Stream of its bytes)."""
    magic = raw.peek(4)
    if magic[:2] == b"\x1f\x8b":
        return Stream(inflate(iter(functools.partial(raw.read, CHUNK), b""), 31))
    if magic == b"pbzx":
        return Stream(pbzx(raw))
    return raw


# -------------------------------------------------------------------- cpio --

def cpio_entries(s):
    """(name, size, stream positioned at its data, mode) for each entry of an odc or newc cpio stream.
    The caller reads or skips exactly size bytes before asking for the next entry."""
    while True:
        magic = s.read(6)
        if magic == b"070707":
            h = s.read(70)
            if len(h) < 70:
                return
            mode, namesize, size = int(h[12:18], 8), int(h[53:59], 8), int(h[59:70], 8)
            name = s.read(namesize).rstrip(b"\0").decode("utf-8", "replace")
            pad = 0
        elif magic in (b"070701", b"070702"):
            h = s.read(104)
            if len(h) < 104:
                return
            mode, size, namesize = int(h[8:16], 16), int(h[48:56], 16), int(h[88:96], 16)
            name = s.read(namesize).rstrip(b"\0").decode("utf-8", "replace")
            s.skip((4 - (110 + namesize) % 4) % 4)
            pad = (4 - size % 4) % 4
        else:
            return
        if name == "TRAILER!!!":
            return
        yield name, size, s, mode
        s.skip(pad)


# --------------------------------------------------------------------- xar --

def xar_files(stream):
    """(path, offset, length, encoding) of every file in a xar archive, offsets counted from the start
    of the archive; reads the archive's header and table of contents from stream."""
    header = stream.read(28)
    if len(header) < 28 or header[:4] != b"xar!":
        return []
    size, _version, toc_len, toc_raw_len = struct.unpack(">HHQQ", header[4:24])
    if toc_len > MAX_TOC_BYTES or toc_raw_len > MAX_TOC_BYTES or size < 28:
        raise TooBig("xar table of contents too big")
    stream.skip(size - 28)
    toc = zlib.decompress(stream.read(toc_len))
    heap = size + toc_len
    out = []

    def walk(node, prefix):
        for item in node.findall("file"):
            path = prefix + (item.findtext("name") or "")
            data = item.find("data")
            if data is not None and item.findtext("type") == "file":
                encoding = (data.find("encoding").get("style") if data.find("encoding") is not None else "")
                out.append((path, heap + int(data.findtext("offset") or 0), int(data.findtext("length") or 0),
                            encoding))
            walk(item, path + "/")

    walk(ET.fromstring(toc).find("toc"), "")  # expat limits entity expansion; nothing external is resolved
    return out


# --------------------------------------------------------------- Info.plist --

def best(found):
    """The main app among the Info.plists found: the one with BridgePatcher's build info
    ("Github"), else the least nested one with a version."""
    found = [(depth, p) for depth, p in found if isinstance(p, dict) and p.get("CFBundleShortVersionString")]
    for _depth, p in found:
        if isinstance(p.get("Github"), dict):
            return p
    return min(found, key=lambda x: x[0])[1] if found else None


def parse_plist(data):
    try:
        return plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError, ET.ParseError):
        return None  # a broken plist in an untrusted asset just isn't judged


def search_payload(raw, encoding, found):
    """Look for the app's Info.plist in a component's Payload (raw: Stream of its bytes as stored).
    Adds what it finds to found; True once it found the main app."""
    if "gzip" in encoding:
        raw = Stream(inflate(iter(functools.partial(raw.read, CHUNK), b""), 15))
    for entry, size, s, _mode in cpio_entries(payload_stream(raw)):
        if APP_PLIST.match(entry) and size <= MAX_PLIST_BYTES and entry.count(".app/") == 1:
            plist = parse_plist(s.read(size))
            found.append((entry.count("/"), plist))
            if isinstance(plist, dict) and isinstance(plist.get("Github"), dict):
                return True
        else:
            s.skip(size)
    return False


def from_pkg(chunks):
    """Info.plist of the app in a flat package, read from start to end as one stream of chunks."""
    stream = Stream(chunks)
    found = []
    files = xar_files(stream)
    at = stream.consumed()
    for _name, offset, length, encoding in sorted(f for f in files if os.path.basename(f[0]) == "Payload"):
        if offset < at:
            continue  # overlaps what was read already: not a package Build-Project.command makes
        stream.skip(offset - at)
        raw = Stream(part(stream, length))
        done = search_payload(raw, encoding, found)
        raw.skip(MAX_UNPACKED_BYTES)  # the rest of this payload
        at = offset + length
        if done:
            break
    stream.skip(MAX_UNPACKED_BYTES)  # read to the end, so the whole asset is hashed
    return best(found)


def from_zip(path):
    found = []
    with zipfile.ZipFile(path) as z:  # only one member is read; nothing is extracted
        for info in z.infolist():
            if APP_PLIST.match(info.filename) and info.filename.count(".app/") == 1 \
                    and info.file_size <= MAX_PLIST_BYTES:
                with z.open(info) as member:
                    found.append((info.filename.count("/"), parse_plist(member.read(MAX_PLIST_BYTES + 1))))
    return best(found)


# ----------------------------------------------------------------- unpack --
# For the malware scan of lookalike repositories (lookalike_malware.py): a flat package's files are
# written to a folder so the scanners can read them. Nothing is run; only regular files are written
# (symlinks become small files holding their target), always inside the folder.

S_IFMT, S_IFREG, S_IFLNK = 0o170000, 0o100000, 0o120000


def safe_join(folder, name):
    """folder/name, or None when name would leave the folder (absolute paths are taken as relative)."""
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return os.path.join(folder, *parts)


def write_file(path, chunks):
    """Write chunks to a new file at path (never through a symlink or over an existing file).
    False when the file can't be created there; chunks are left unread then."""
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        return False
    with os.fdopen(fd, "wb") as f:
        for block in chunks:
            f.write(block)
    return True


def unpack_cpio(s, folder):
    """Write the regular files (and symlinks, as text) of a cpio stream into folder."""
    for name, size, entry, mode in cpio_entries(s):
        target = safe_join(folder, name)
        if mode & S_IFMT not in (S_IFREG, S_IFLNK) or target is None or not write_file(target, part(entry, size)):
            entry.skip(size)


def unpack_pkg(url, folder, expected_sha256=None):
    """Download a flat package (https://github.com/... only) and write its files into folder: the
    contents of every Payload and Scripts archive under "<component>/Payload.contents/" (or
    Scripts.contents), the other files of the package (Distribution, PackageInfo, ...) as they are.
    Raises when it can't be read (too big, not a valid package, checksum mismatch, ...)."""
    source = Hashed(url)
    try:
        stream = Stream(iter(source))
        files = xar_files(stream)
        at = stream.consumed()
        for name, offset, length, encoding in sorted(files, key=lambda f: f[1]):
            if offset < at:
                continue  # overlaps what was read already
            stream.skip(offset - at)
            raw = Stream(part(stream, length))
            data = Stream(inflate(iter(functools.partial(raw.read, CHUNK), b""), 15)) if "gzip" in encoding else raw
            if os.path.basename(name) in ("Payload", "Scripts"):
                target = safe_join(folder, name + ".contents")
                if target:
                    unpack_cpio(payload_stream(data), target)
            else:
                target = safe_join(folder, name)
                if target:
                    write_file(target, iter(functools.partial(data.read, CHUNK), b""))
            raw.skip(MAX_UNPACKED_BYTES)  # the rest of this file
            at = offset + length
        stream.skip(MAX_UNPACKED_BYTES)  # read to the end, so the whole asset is hashed
        source.verify(expected_sha256)
    except (zlib.error, lzma.LZMAError, gzip.BadGzipFile, ET.ParseError, struct.error, ValueError) as e:
        raise ValueError(f"not a readable .pkg ({e})") from e
    finally:
        source.close()


def supported(name):
    return name.lower().endswith((".pkg", ".zip"))


def app_info(url, name, expected_sha256=None):
    """Info.plist (dict) of the app a release asset ships, or None when the asset type isn't
    supported or holds no app. Raises when it can't be read (too big, not a valid archive, checksum
    mismatch, ...)."""
    if not supported(name):
        return None
    try:
        if name.lower().endswith(".pkg"):
            source = Hashed(url)
            try:
                info = from_pkg(iter(source))
                source.verify(expected_sha256)
            finally:
                source.close()
            return info
        path = download(url, expected_sha256)
        try:
            return from_zip(path)
        finally:
            remove(path)
    except (zipfile.BadZipFile, zlib.error, lzma.LZMAError, gzip.BadGzipFile, ET.ParseError,
            struct.error) as e:
        raise ValueError(f"not a readable {os.path.splitext(name)[1]} ({e})") from e
