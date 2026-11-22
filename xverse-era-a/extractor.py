#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Xverse Wallet extractor — emits $xverse$ hashes (mode 90036).

Xverse (Bitcoin/Stacks) keeps its vault in chrome.storage.local:

  era B (SeedVault, ext v0.22-v0.49):
      records `passwordSalt` (64-hex string) + `encryptedKey` (hex blob)
  era C (MasterVault, ext v0.50+, current):
      records `vault::passwordSalt` (64-hex string) + `vault::encryptionVault`

Both eras derive the key the same way:

      passwordHash = argon2id(password, utf8(passwordSalt-hex-string),
                              t=3, m=65536, p=4, hashLen=16)
      key          = utf8(hex(passwordHash))         (32 ascii bytes)
      blob         = iv(16) || AES-256-GCM(key, iv).ct || tag(16)

Era B encrypts the bip39 entropy as a hex string (the 32-byte sample must
be [0-9a-f]{32}); era C encrypts the vault JSON
{"seedEncryptionKey":"<32hex>",...} (the sample starts with that prefix).
The GCM tag is not needed (CTR prefix decrypt); the line carries no seed
material.

Hash grammar (our module 90036):

    $xverse$<b|c>$<passwordSalt>$<iv hex>$<first 32 ct bytes hex>

NOTE: the argon2 salt is the 64 ASCII characters of the passwordSalt hex
string itself. Cracking requires hashcat v8.0.0 or newer (argon2).
"""

import argparse
import hashlib
import hmac
import json
import os
import platform
import re
import shutil
import sys
import tempfile
import threading

MODE = 90036
MODE_A = 90037
OUTPUT_NAME = "xverse-hash.txt"      # eras b/c (current)
OUTPUT_NAME_A = "xverse-a-hash.txt"  # era a (legacy 2021-2022)

XVERSE_EXTENSION_ID = "idnnbdplmphpflfnlkomgpfbpcgelopg"
LES_NAME = "Local Extension Settings"
MAX_DEPTH = 6
SKIP_DIRS = {
    "cache", "caches", "cache2", "cachestorage", "code cache", "gpucache",
    "shadercache", "dawngraphitecache", "dawnwebglcache", "service worker",
    "temp", "tmp", "crashpad",
}

BROWSER_LABELS = {
    "chrome sxs": "Chrome Canary",
    "chrome": "Google Chrome",
    "microsoft edge": "Microsoft Edge",
    "edge": "Microsoft Edge",
    "brave-browser": "Brave",
    "vivaldi": "Vivaldi",
    "opera stable": "Opera",
    "opera": "Opera",
    "com.operasoftware.opera": "Opera",
    "yandexbrowser": "Yandex Browser",
    "whale": "Naver Whale",
    "chromium": "Chromium",
}

ERA_LABELS = {"b": "Xverse SeedVault (era b)", "c": "Xverse MasterVault (era c)"}
RECORD_SALTS = {"b": b"passwordSalt", "c": b"vault::passwordSalt"}
RECORD_BLOBS = {"b": b"encryptedKey", "c": b"vault::encryptionVault"}

# era a (legacy): the blob lives in the `persist:walletState` chrome.storage
# record (field `encryptedSeed`), but its argon2 salt is the plain `salt`
# key of the extension's DOM localStorage (a DIFFERENT LevelDB: the
# profile's "Local Storage\leveldb" next to "Local Extension Settings")
DOM_LS_DIRNAME = os.path.join("Local Storage", "leveldb")

# the era-B/C passwordHash of the self-test fixture (GPU-validated);
# stdlib has no argon2, so the self-test verifies the cipher chain from
# this known derived key instead of re-deriving it
ST_PASSWORD_HASH = "5a73ef25268b50d621c3975352b84bb5"

# same for era A: the argon2i hash of the fixture (GPU-validated); the
# PBKDF2 + HMAC chain below it IS stdlib and gets verified end-to-end
ST_ARGON2I_HASH = ("152a7d596602f9997ce32b70e20dcc6f52e5ea345beec5360f985"
                   "22986eac16832f23818472c5d72af451b256a9f69ac")


# ------------------------------------------------------------------ hashing

def format_hash(era, salt_str, iv_hex, ct32):
    return "$xverse$%s$%s$%s$%s" % (era, salt_str, iv_hex, ct32.hex())


def vault_key(password_hash_hex):
    """The AES-256-GCM key: utf8 of the lowercase hex passwordHash."""
    return password_hash_hex.encode("ascii")


# ---------------------------------------------------------------- extraction

def _json_layers(value):
    """Decode a chrome.storage record value: an optional 0x01 type byte,
    then JSON — possibly a JSON string inside JSON. -> object or None."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value)
        if value[:1] == b"\x01":
            value = value[1:]
        try:
            text = value.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return None
    else:
        text = value
    if not isinstance(text, str):
        return None
    try:
        obj = json.loads(text)
    except ValueError:
        return None
    for _ in range(2):  # unwrap a JSON-encoded JSON string
        if isinstance(obj, str):
            try:
                obj = json.loads(obj)
            except ValueError:
                break  # a plain string value (e.g. the salt hex), keep it
    return obj


def parse_salt_record(value):
    """A passwordSalt record -> the 64-char hex string, or None."""
    obj = _json_layers(value)
    if not isinstance(obj, str):
        return None
    if not re.fullmatch(r"[0-9a-fA-F]{64}", obj):
        return None
    return obj.lower()


def parse_blob_record(value):
    """An encryptedKey/encryptionVault record (hex of iv||ct||tag) ->
    {iv_hex, ct32}, or None."""
    obj = _json_layers(value)
    if not isinstance(obj, str):
        return None
    if len(obj) < 128 or len(obj) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", obj):
        return None
    iv_hex = obj[:32].lower()
    try:
        ct32 = bytes.fromhex(obj[32:96])
    except ValueError:
        return None
    return {"iv_hex": iv_hex, "ct32": ct32}


def format_hash_a(ls_salt, salt16_hex, hmac_hex, ct):
    return "$xverse-a$%s$%s$%s$%s" % (ls_salt, salt16_hex, hmac_hex, ct.hex())


def parse_ls_salt(value):
    """DOM localStorage `salt` value -> 32-char hex string, or None.
    DOM localStorage values are prefixed: 0x01 = utf-8, 0x00 = utf-16-le."""
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bytes, bytearray)) and len(value) > 1:
        value = bytes(value)
        try:
            if value[0] == 0x01:
                text = value[1:].decode("utf-8", "strict")
            elif value[0] == 0x00:
                text = value[1:].decode("utf-16-le", "strict")
            else:
                return None
        except UnicodeDecodeError:
            return None
    else:
        return None
    text = text.strip().strip('"')
    if not re.fullmatch(r"[0-9a-fA-F]{32}", text):
        return None
    return text.lower()


def parse_encrypted_seed(value):
    """`persist:walletState` record -> {salt16_hex, hmac_hex, ct}, or None.
    redux-persist stores the hex blob as a JSON string field; the blob is
    hex(salt16 || hmac32 || ct) with ct = 32 bytes (12 words) or 48 (24)."""
    obj = _json_layers(value)
    if not isinstance(obj, dict):
        return None
    seed = _json_layers(obj.get("encryptedSeed"))
    if not isinstance(seed, str):
        return None
    if len(seed) < 160 or len(seed) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", seed):
        return None
    ct = bytes.fromhex(seed[96:])
    if len(ct) not in (32, 48):
        return None
    return {"salt16_hex": seed[:32].lower(), "hmac_hex": seed[32:96].lower(),
            "ct": ct}


def copy_to_temp(src_dir, dst):
    """Copy a (possibly locked) LevelDB folder; returns the list of file
    paths that could not be copied. The originals are only read."""
    failures = []
    for root, _dirs, files in os.walk(src_dir):
        rel = os.path.relpath(root, src_dir)
        target = os.path.join(dst, rel)
        os.makedirs(target, exist_ok=True)
        for name in files:
            if name == "LOCK":  # the lock file itself is never needed
                continue
            s = os.path.join(root, name)
            try:
                shutil.copy2(s, os.path.join(target, name))
            except OSError:
                failures.append(os.path.join(rel, name))
    return failures


def scan_dir(db_dir):
    """Scan an Xverse extension LevelDB directory for the era-A/B/C vault
    records (era A also reads the profile's DOM localStorage LevelDB next
    door). The folders are copied to a temporary directory first so a
    running browser's file locks cannot break the read."""
    salts = {"b": [], "c": []}
    blobs = {"b": [], "c": []}
    a_salts = []
    a_blobs = []
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        failures = copy_to_temp(db_dir, tmp)
        for key, value in leveldb_payloads(tmp):
            if not isinstance(key, bytes):
                continue
            name = key.split(b"\x00\x01")[-1]
            if name == b"persist:walletState":
                seed = parse_encrypted_seed(value)
                if seed is not None and seed not in a_blobs:
                    a_blobs.append(seed)
                continue
            for era in ("b", "c"):
                if name == RECORD_SALTS[era]:
                    s = parse_salt_record(value)
                    if s is not None and s not in salts[era]:
                        salts[era].append(s)
                elif name == RECORD_BLOBS[era]:
                    b = parse_blob_record(value)
                    if b is not None and b not in blobs[era]:
                        blobs[era].append(b)
    # era A: the argon2 salt lives in the DOM localStorage LevelDB
    dom_dir = os.path.join(os.path.dirname(os.path.dirname(db_dir)),
                           DOM_LS_DIRNAME)
    if os.path.isdir(dom_dir):
        with tempfile.TemporaryDirectory() as tmp:
            failures += ["Local Storage/" + f
                         for f in copy_to_temp(dom_dir, tmp)]
            for key, value in leveldb_payloads(tmp):
                if not isinstance(key, bytes):
                    continue
                if key.endswith(b"\x00\x01salt") or key == b"salt":
                    s = parse_ls_salt(value)
                    if s is not None and s not in a_salts:
                        a_salts.append(s)
    entries = []
    seen = set()
    warns = []
    if a_blobs and not a_salts:
        warns.append("persist:walletState record found but no localStorage "
                     "salt (era a)")
    if a_salts and not a_blobs:
        warns.append("localStorage salt found but no persist:walletState "
                     "record (era a)")
    if len(a_salts) > 1:
        warns.append("multiple localStorage salt values found, pairing "
                     "each with every legacy blob")
    for s in a_salts:
        for bl in a_blobs:
            h = format_hash_a(s, bl["salt16_hex"], bl["hmac_hex"], bl["ct"])
            if h in seen:
                continue
            seen.add(h)
            entries.append({"hash": h, "mode": MODE_A,
                            "where": "Xverse legacy (era a)"})
    for era in ("b", "c"):
        if salts[era] and not blobs[era]:
            warns.append("%s record found but no %s"
                         % (RECORD_SALTS[era].decode(),
                            RECORD_BLOBS[era].decode()))
            continue
        if blobs[era] and not salts[era]:
            warns.append("%s record found but no %s"
                         % (RECORD_BLOBS[era].decode(),
                            RECORD_SALTS[era].decode()))
            continue
        if len(salts[era]) > 1:
            warns.append("multiple %s values found, pairing each with "
                         "every %s blob" % (RECORD_SALTS[era].decode(),
                                            RECORD_BLOBS[era].decode()))
        for s in salts[era]:
            for b in blobs[era]:
                h = format_hash(era, s, b["iv_hex"], b["ct32"])
                if h in seen:
                    continue
                seen.add(h)
                entries.append({"hash": h, "mode": MODE,
                                "where": ERA_LABELS[era]})
    note = None
    if not entries:
        note = ("%s: no Xverse vault records found (the wallet may be "
                "empty or never set up)" % db_dir)
    if warns:
        w = "%s: %s" % (db_dir, "; ".join(warns))
        note = "%s; %s" % (note, w) if note else w
    if failures:
        warn = ("%s: could not copy %s — close the browser and run again"
                % (db_dir, ", ".join(failures)))
        note = "%s; %s" % (note, warn) if note else warn
    return {"hashes": entries, "note": note}


# ---------------------------------------------------------------- discovery

def path_parts(path):
    return [p for p in re.split(r"[\\/]+", path) if p]


def scan_roots():
    system = platform.system()
    home = os.path.expanduser("~")
    if system == "Windows":
        roots = [
            os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local")),
            os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming")),
        ]
    elif system == "Darwin":
        roots = [os.path.join(home, "Library", "Application Support")]
    else:
        roots = [os.path.join(home, ".config")]
    return [r for r in roots if os.path.isdir(r)]


def browser_label_for(les_path):
    parts = path_parts(les_path)
    lowered = [p.lower() for p in parts]
    for p in lowered:
        if p in BROWSER_LABELS:
            return BROWSER_LABELS[p]
    if "user data" in lowered:
        i = lowered.index("user data")
        if i > 0:
            return parts[i - 1]
    return parts[-2] if len(parts) >= 2 else les_path


def find_stores():
    """-> [{'path', 'where'}] Xverse extension LevelDB directories."""
    found = []
    seen = set()
    for root in scan_roots():
        stack = [(root, 0)]
        while stack:
            path, depth = stack.pop()
            if depth >= MAX_DEPTH:
                continue
            try:
                with os.scandir(path) as it:
                    for entry in it:
                        try:
                            if not entry.is_dir(follow_symlinks=False):
                                continue
                        except OSError:
                            continue
                        if entry.name == XVERSE_EXTENSION_ID \
                                and os.path.basename(path) == LES_NAME:
                            if entry.path not in seen:
                                seen.add(entry.path)
                                found.append({
                                    "path": entry.path,
                                    "where": "%s, %s" % (
                                        browser_label_for(path),
                                        os.path.basename(
                                            os.path.dirname(path)))})
                        elif entry.name.lower() not in SKIP_DIRS:
                            stack.append((entry.path, depth + 1))
            except OSError:
                continue
    return sorted(found, key=lambda s: s["path"])


# ------------------------------------------------------------------ leveldb

LOG_BLOCK_SIZE = 32768
SSTABLE_MAGIC = 0xDB4775248B80FB57


def _varint(data, pos):
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
    raise ValueError("truncated varint")


def snappy_decompress(data):
    """Decompress a raw (unframed) Snappy stream."""
    _, pos = _varint(data, 0)
    out = bytearray()
    while pos < len(data):
        tag = data[pos]
        pos += 1
        kind = tag & 0x03
        if kind == 0:  # literal
            n = tag >> 2
            if n < 60:
                length = n + 1
            else:
                nbytes = n - 59
                length = int.from_bytes(data[pos:pos + nbytes], "little") + 1
                pos += nbytes
            out += data[pos:pos + length]
            pos += length
        else:
            if kind == 1:      # copy, 1-byte offset
                length = ((tag >> 2) & 0x07) + 4
                offset = ((tag & 0xE0) << 3) | data[pos]
                pos += 1
            elif kind == 2:    # copy, 2-byte offset
                length = (tag >> 2) + 1
                offset = int.from_bytes(data[pos:pos + 2], "little")
                pos += 2
            else:              # copy, 4-byte offset
                length = (tag >> 2) + 1
                offset = int.from_bytes(data[pos:pos + 4], "little")
                pos += 4
            if offset < 1 or offset > len(out):
                raise ValueError("snappy: invalid copy offset")
            for _ in range(length):
                out.append(out[-offset])
    return bytes(out)


def _read_block(data, offset, size):
    block = data[offset:offset + size]
    trailer = data[offset + size:offset + size + 5]
    if len(block) < size or len(trailer) < 5:
        raise ValueError("truncated block")
    ctype = trailer[0]
    if ctype == 0:
        return block
    if ctype == 1:
        return snappy_decompress(block)
    raise ValueError("unknown block compression type %d" % ctype)


def _entry_items(block):
    """(internal_key, value) of all entries in an uncompressed block
    (restart-point format with prefix-shared keys)."""
    if len(block) < 4:
        return
    try:
        num_restarts = int.from_bytes(block[-4:], "little")
        limit = len(block) - 4 - 4 * num_restarts
        pos = 0
        key = b""
        while pos < limit:
            shared, pos = _varint(block, pos)
            non_shared, pos = _varint(block, pos)
            vlen, pos = _varint(block, pos)
            key = key[:shared] + bytes(block[pos:pos + non_shared])
            pos += non_shared
            yield key, bytes(block[pos:pos + vlen])
            pos += vlen
    except (ValueError, IndexError):
        return


def sstable_payloads(path):
    """Decompressed contents of every data block in a .ldb/.sst file."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return
    if len(data) < 48 or int.from_bytes(data[-8:], "little") != SSTABLE_MAGIC:
        return
    try:
        footer = data[-48:-8]
        _, p = _varint(footer, 0)
        _, p = _varint(footer, p)
        idx_off, p = _varint(footer, p)
        idx_size, p = _varint(footer, p)
        index_block = _read_block(data, idx_off, idx_size)
    except (ValueError, IndexError):
        return
    for handle in _entry_values(index_block):
        try:
            off, q = _varint(handle, 0)
            size, q = _varint(handle, q)
            yield _read_block(data, off, size)
        except (ValueError, IndexError):
            continue


def _entry_values(block):
    """Values of all entries in an uncompressed block (restart-point format)."""
    if len(block) < 4:
        return
    try:
        num_restarts = int.from_bytes(block[-4:], "little")
        limit = len(block) - 4 - 4 * num_restarts
        pos = 0
        while pos < limit:
            _, pos = _varint(block, pos)
            non_shared, pos = _varint(block, pos)
            vlen, pos = _varint(block, pos)
            pos += non_shared
            yield bytes(block[pos:pos + vlen])
            pos += vlen
    except (ValueError, IndexError):
        return


def log_record_payloads(path):
    """Logical record payloads (WriteBatches) from a .log file, reassembled
    across 32 KiB block fragments."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return
    fragments = []
    for block_start in range(0, len(data), LOG_BLOCK_SIZE):
        block = data[block_start:block_start + LOG_BLOCK_SIZE]
        pos = 0
        while pos + 7 <= len(block):
            length = int.from_bytes(block[pos + 4:pos + 6], "little")
            rtype = block[pos + 6]
            pos += 7
            if rtype == 0 and length == 0:
                break
            if pos + length > len(block):
                break
            payload = block[pos:pos + length]
            pos += length
            if rtype == 1:
                yield bytes(payload)
                fragments = []
            elif rtype == 2:
                fragments = [payload]
            elif rtype == 3:
                if fragments:
                    fragments.append(payload)
            elif rtype == 4:
                if fragments:
                    fragments.append(payload)
                    yield b"".join(fragments)
                    fragments = []


def writebatch_items(record):
    """All (key, value) pairs stored by a WriteBatch log record."""
    if len(record) < 12:
        return
    pos = 12
    try:
        while pos < len(record):
            rtype = record[pos]
            pos += 1
            klen, pos = _varint(record, pos)
            key = bytes(record[pos:pos + klen])
            pos += klen
            if rtype == 1:
                vlen, pos = _varint(record, pos)
                yield key, bytes(record[pos:pos + vlen])
                pos += vlen
            elif rtype == 0:
                continue
            else:
                break
    except (ValueError, IndexError):
        return


def leveldb_payloads(db_dir):
    """Every (user_key, value) pair we can read from a LevelDB directory.
    user_key is None when it cannot be determined."""
    try:
        names = os.listdir(db_dir)
    except OSError:
        return
    for name in sorted(names):
        low = name.lower()
        if low.endswith((".ldb", ".sst")):
            for block in sstable_payloads(os.path.join(db_dir, name)):
                for ikey, value in _entry_items(block):
                    # internal key = user key + 8-byte (sequence<<8 | type)
                    user_key = ikey[:-8] if len(ikey) >= 8 else None
                    yield user_key, value
    for name in sorted(names):
        if name.lower().endswith(".log"):
            for record in log_record_payloads(os.path.join(db_dir, name)):
                for key, value in writebatch_items(record):
                    yield key, value


# ---------------------------------------------------------------- interaction

GRAY = "\x1b[90m"
CYAN = "\x1b[36m"
RESET = "\x1b[0m"


def _enable_console_features():
    """Enable ANSI colors and UTF-8 output on the Windows console."""
    if os.name != "nt":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleOutputCP(65001)  # UTF-8
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


class Spinner:
    """A \\|/- spinner inside a terminal-width box, redrawn in place."""

    FRAMES = "\\|/-"

    def __init__(self, text):
        self.text = text
        self.inner = max(1, shutil.get_terminal_size().columns - 2)
        self.rows = -(-len(text + " " + self.FRAMES[0]) // self.inner) + 2
        self._stop = None
        self._thread = None

    def _render(self, frame):
        border = "+" + "=" * self.inner + "+"
        line = "%s %s" % (self.text, frame)
        chunks = [line[i:i + self.inner]
                  for i in range(0, len(line), self.inner)]
        rows = [border] + ["|" + c + " " * (self.inner - len(c)) + "|"
                           for c in chunks] + [border]
        return "\n".join(rows) + "\n"

    def __enter__(self):
        if sys.stdout.isatty():
            sys.stdout.write(self._render(self.FRAMES[0]))
            sys.stdout.flush()
            self._stop = threading.Event()
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        else:
            print(self.text)
        return self

    def _spin(self):
        i = 1
        while not self._stop.is_set():
            sys.stdout.write("\x1b[%dA" % self.rows + "\x1b[J" +
                             self._render(self.FRAMES[i % 4]))
            sys.stdout.flush()
            i += 1
            self._stop.wait(0.1)

    def __exit__(self, *exc):
        if self._thread:
            self._stop.set()
            self._thread.join()
        return False


def _read_key():
    """One keypress -> 'up', 'down', 'enter', or None."""
    if os.name == "nt":
        import msvcrt
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):
            return "enter"
        if ch in ("\x00", "\xe0"):  # special-key prefix
            return {"H": "up", "P": "down"}.get(msvcrt.getwch())
        return None
    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch in ("\r", "\n"):
            return "enter"
        if ch == "\x1b" and sys.stdin.read(1) == "[":
            return {"A": "up", "B": "down"}.get(sys.stdin.read(1))
        return None
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _visible_len(s):
    """Length of a string without ANSI escape sequences."""
    return len(re.sub(r"\x1b\[[0-9;]*m", "", s))


def print_box(lines):
    """Print lines inside a terminal-width frame, hard-wrapping long ones.
    The frame is drawn with colored spaces, so copying the text does not
    pick up any border characters. On a non-terminal, prints as-is."""
    if not sys.stdout.isatty():
        for line in lines:
            print(line)
        return
    inner = max(1, shutil.get_terminal_size().columns - 2)
    border = "+" + "=" * inner + "+"
    print(border)
    for line in lines:
        if line.startswith("[Hash] ") and len(line) > inner:
            # Borderless wrap: no right border on the first row (it fills the
            # full terminal width) and no left border on continuations, so
            # copying the wrapped hash does not pick up border characters.
            print("|" + line[:inner + 1])
            rest = line[inner + 1:]
            for i in range(0, len(rest), inner):
                chunk = rest[i:i + inner]
                print(chunk + " " * (inner + 1 - len(chunk)) + "|")
        else:
            chunks = [line[i:i + inner] for i in range(0, len(line), inner)] \
                     if line else [""]
            for chunk in chunks:
                print("|" + chunk + " " * (inner - len(chunk)) + "|")
    print(border)


def arrow_select(title, options, default=0):
    """Interactive selector in a box: up/down arrows, Enter to confirm.

    options: list of (text, hint) tuples; the hint is rendered gray and is
    only visible while the cursor is NOT on that option.
    The whole box is erased after the selection, leaving no trace.
    Falls back to a numbered prompt when there is no real terminal, and to an
    unboxed menu when the terminal is too narrow for the box.
    """
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return prompt_choice(
            title, [t + ((" " + h) if h else "") for t, h in options], default)
    _enable_console_features()
    sel = default

    hint_text = "(up/down, Enter)"
    inner = max([len(title) + 1 + len(hint_text)] +
                [2 + len(text) + (1 + len(hint) if hint else 0)
                 for text, hint in options])
    use_box = inner <= shutil.get_terminal_size().columns - 2
    rows = len(options) + 3 if use_box else len(options) + 1

    def row(content):
        pad = inner - _visible_len(content)
        return "|" + content + " " * max(0, pad) + "|"

    def render():
        if use_box:
            print("\x1b[2K" + "+" + "=" * inner + "+")
        title_line = title + " " + GRAY + hint_text + RESET
        print("\x1b[2K" + (row(title_line) if use_box else title_line))
        for i, (text, hint) in enumerate(options):
            pointer = "> " if i == sel else "· "
            body = pointer + text + ((" " + GRAY + hint + RESET)
                                     if hint and i != sel else "")
            line = CYAN + body + RESET if i == sel else body
            print("\x1b[2K" + (row(line) if use_box else line))
        if use_box:
            print("\x1b[2K" + "+" + "=" * inner + "+")

    render()
    while True:
        key = _read_key()
        if key == "enter":
            # erase the whole menu (box or plain lines); the cursor sits one
            # row below the last rendered line
            sys.stdout.write("\x1b[%dA" % rows + "\x1b[J")
            return sel
        if key == "up" and sel > 0:
            sel -= 1
        elif key == "down" and sel < len(options) - 1:
            sel += 1
        else:
            continue
        sys.stdout.write("\x1b[%dA" % rows)
        render()
        sys.stdout.flush()


def prompt_choice(title, options, default=0):
    """Numbered menu. Returns the 0-based index; Enter picks the default."""
    print("\n" + title)
    for i, opt in enumerate(options):
        print("  %d) %s" % (i + 1, opt))
    while True:
        try:
            raw = input("Enter number [%d]: " % (default + 1)).strip()
        except EOFError:
            return default
        if raw == "":
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw) - 1
        print("Please enter a number between 1 and %d." % len(options))


def manual_pick_path():
    """Native folder-picker dialog (tkinter); falls back to typed input."""
    path = None
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        path = filedialog.askdirectory(
            title="Select the Xverse extension storage folder")
        root.destroy()
    except Exception:
        path = None
    if not path:
        try:
            raw = input("Enter the extension storage folder path: ").strip().strip('"')
        except EOFError:
            raw = ""
        path = raw or None
    return path


# ---------------------------------------------------------------- self-test

# Pure-python AES-256-GCM (stdlib only) — used ONLY by --self-test to
# verify the full crypto chain against the GPU-verified fixtures below.


def _gf_mul8(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def _build_sbox():
    sbox = []
    for b in range(256):
        inv = 0
        if b:
            a, n, inv = b, 254, 1  # inv = b**254 in GF(2^8)
            while n:
                if n & 1:
                    inv = _gf_mul8(inv, a)
                a = _gf_mul8(a, a)
                n >>= 1
        s = inv
        for i in range(1, 5):
            s ^= ((inv << i) | (inv >> (8 - i))) & 0xFF
        sbox.append(s ^ 0x63)
    return tuple(sbox)


_AES_SBOX = _build_sbox()
_AES_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40)


def _aes256_key_expand(key):
    """AES-256 key schedule -> 15 round keys (column-major bytes)."""
    w = [list(key[4 * i:4 * i + 4]) for i in range(8)]
    for i in range(8, 60):
        temp = list(w[i - 1])
        if i % 8 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_AES_SBOX[b] for b in temp]
            temp[0] ^= _AES_RCON[i // 8 - 1]
        elif i % 8 == 4:
            temp = [_AES_SBOX[b] for b in temp]
        w.append([w[i - 8][j] ^ temp[j] for j in range(4)])
    return [bytes(w[4 * r] + w[4 * r + 1] + w[4 * r + 2] + w[4 * r + 3])
            for r in range(15)]


def _mix_column(col):
    a, b, c, d = col
    xa, xb, xc, xd = (_gf_mul8(2, a), _gf_mul8(2, b),
                      _gf_mul8(2, c), _gf_mul8(2, d))
    return [xa ^ (xb ^ b) ^ c ^ d,
            a ^ xb ^ (xc ^ c) ^ d,
            a ^ b ^ xc ^ (xd ^ d),
            (xa ^ a) ^ b ^ c ^ xd]


def _aes_encrypt_block(round_keys, block):
    state = [block[i] ^ round_keys[0][i] for i in range(16)]
    for rnd in range(1, 15):
        state = [_AES_SBOX[b] for b in state]
        # ShiftRows (state index i = row i%4, column i//4)
        state = [state[r + 4 * ((c + r) % 4)]
                 for c in range(4) for r in range(4)]
        if rnd < 14:
            mixed = []
            for c in range(4):
                mixed += _mix_column(state[4 * c:4 * c + 4])
            state = mixed
        state = [state[i] ^ round_keys[rnd][i] for i in range(16)]
    return bytes(state)


_GCM_R = 0xE1000000000000000000000000000000


def _gf_mul128(x, y):
    """x * y in GF(2^128) with the GCM reduction polynomial."""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _GCM_R
        else:
            v >>= 1
    return z


def _pad16(data):
    return data + b"\x00" * (-len(data) % 16)


def _ghash(h_bytes, data):
    h = int.from_bytes(h_bytes, "big")
    y = 0
    for off in range(0, len(data), 16):
        y = _gf_mul128(y ^ int.from_bytes(data[off:off + 16], "big"), h)
    return y.to_bytes(16, "big")


def _inc32(block):
    return block[:12] + ((int.from_bytes(block[12:], "big") + 1)
                         & 0xFFFFFFFF).to_bytes(4, "big")


def _gctr(round_keys, j0, data):
    out = bytearray()
    cb = j0
    for off in range(0, len(data), 16):
        cb = _inc32(cb)
        ks = _aes_encrypt_block(round_keys, cb)
        chunk = data[off:off + 16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


def _gcm_open(key, iv, data):
    """AES-256-GCM open: data = ciphertext || 16-byte tag, 96-bit iv.
    The tag is verified FIRST; -> plaintext, or None on tag failure."""
    ct, tag = data[:-16], data[-16:]
    rk = _aes256_key_expand(key)
    h = _aes_encrypt_block(rk, bytes(16))
    if len(iv) == 12:
        j0 = iv + b"\x00\x00\x00\x01"
    else:  # J0 = GHASH_H(pad16(iv) || 0^64 || [len(iv)]64)
        j0 = _ghash(h, _pad16(iv) + bytes(8) + (len(iv) * 8).to_bytes(8, "big"))
    lens = (0).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
    s = _ghash(h, _pad16(ct) + lens)
    expected = bytes(a ^ b for a, b in zip(_aes_encrypt_block(rk, j0), s))
    if expected != tag:
        return None
    return _gctr(rk, j0, ct)


def _varint_bytes(value):
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _write_log(path, entries):
    out = bytearray()
    pos_block = 0
    for key, value in entries:
        batch = (bytes(8) + (1).to_bytes(4, "little")
                 + b"\x01" + _varint_bytes(len(key)) + key
                 + _varint_bytes(len(value)) + value)
        if pos_block + 7 + len(batch) > LOG_BLOCK_SIZE:
            out += b"\x00" * (LOG_BLOCK_SIZE - pos_block)
            pos_block = 0
        out += b"\x00\x00\x00\x00" + len(batch).to_bytes(2, "little") + b"\x01" + batch
        pos_block += 7 + len(batch)
    with open(path, "wb") as f:
        f.write(bytes(out))


def _key(name):
    return b"_" + XVERSE_EXTENSION_ID.encode() + b"\x00\x01" + name


# ---------------------------------------------------------------- fixtures

# GPU-verified fixtures (mode 90036, password "xverse-test-1",
# passwordSalt = hex of bytes 0..31, iv = bytes 0..15); the blobs were
# produced by the wallet's own JS crypto (argon2-browser + aes.ts).
ST_PASSWORD = "xverse-test-1"
ST_SALT_STR = ("000102030405060708090a0b0c0d0e0f10111213141516171819"
               "1a1b1c1d1e1f")
ST_IV_HEX = "000102030405060708090a0b0c0d0e0f"

# era B: entropy-hex vault (12 words -> pt = 32 '0' chars)
ST_BLOB_B = (ST_IV_HEX
             + "0f3cc94004353883527f1b2d71f719b0257b674f194ea8cccc796b8d967a0d2c"
             + "de73f25646de31fc1e68def7d551f837")
ST_LINE_B = ("$xverse$b$" + ST_SALT_STR + "$" + ST_IV_HEX
             + "$0f3cc94004353883527f1b2d71f719b0257b674f194ea8cccc796b8d967a0d2c")
ST_PT_B = b"00000000000000000000000000000000"

# era C: MasterVault encryptionVault JSON
ST_BLOB_C = (ST_IV_HEX
             + "442e8a1551614ddd013d526d35ae46ee5e2e2e5d135cf9cdcc286e88"
               "c7295b2a7d07e2760a5114175ce82f3b12724473e172826e4e505bcbc9"
               "55cf6bfc685a5c0135bdb9cef98658d2a11a379ad5ad748cf8047d8e9e"
               "7271d633573d047822c038c2acbeede701f6ce6eee36922aedb632130"
             + "38e3bde5be6d739dcb0d22a1d")
ST_LINE_C = ("$xverse$c$" + ST_SALT_STR + "$" + ST_IV_HEX
             + "$442e8a1551614ddd013d526d35ae46ee5e2e2e5d135cf9cdcc286e88c7295b2a")
ST_PT_C = (b'{"seedEncryptionKey":"a10a55acf6aab87d8800a3ed19c57fe4",'
           b'"dataEncryptionKey":"547d16e746318abc029ded50033fbb57"}')

# era A (legacy): localStorage salt + hex(salt16 || hmac32 || ct) blob
ST_LS_SALT = "000102030405060708090a0b0c0d0e0f"
ST_BLOB_A1 = ("000102030405060708090a0b0c0d0e0f"
              "95e1fb1d5819ecf67aa59841c4cd36167e7c85af4542919406604ff3ae42acb1"
              "e98153feb917447181271c81b0676bd24523145cfc1a03d43ba5bcdef9c60cf7")
ST_LINE_A1 = ("$xverse-a$" + ST_LS_SALT + "$" + ST_BLOB_A1[:32] + "$"
              + ST_BLOB_A1[32:96] + "$" + ST_BLOB_A1[96:])
ST_BLOB_A2 = ("000102030405060708090a0b0c0d0e0f"
              "a5a737c6e1493d28ca63dd66d64611a86aaea570dafb5b22741f5d9d5e0ca087"
              "e98153feb917447181271c81b0676bd2859d519edfefe1428e8af8588270"
              "c6ab2fe87bf3e0221543830ed747cddaf17b")
ST_LINE_A2 = ("$xverse-a$" + ST_LS_SALT + "$" + ST_BLOB_A2[:32] + "$"
              + ST_BLOB_A2[32:96] + "$" + ST_BLOB_A2[96:])


def self_test():
    # --- pure-python AES sanity: FIPS-197 AES-256 vector
    assert _AES_SBOX[0] == 0x63 and _AES_SBOX[1] == 0x7C
    assert _AES_SBOX[255] == 0x16
    rk = _aes256_key_expand(bytes(range(32)))
    assert _aes_encrypt_block(rk, bytes.fromhex("00112233445566778899aabbccddeeff")) \
        == bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")

    # --- 1. record parsing
    for value in (b"\x01" + json.dumps(ST_SALT_STR).encode(),
                  json.dumps(ST_SALT_STR).encode(),
                  b"\x01" + json.dumps(json.dumps(ST_SALT_STR)).encode()):
        assert parse_salt_record(value) == ST_SALT_STR, value
    assert parse_salt_record(b"\x01" + json.dumps(ST_SALT_STR[:-1]).encode()) is None
    assert parse_salt_record(b"\x01" + json.dumps("zz" + ST_SALT_STR[2:]).encode()) is None
    assert parse_salt_record(b"\x01not json") is None
    assert parse_salt_record(None) is None

    b = parse_blob_record(b"\x01" + json.dumps(ST_BLOB_B).encode())
    assert b is not None and b["iv_hex"] == ST_IV_HEX
    assert b["ct32"].hex() == ("0f3cc94004353883527f1b2d71f719b0257b674f19"
                               "4ea8cccc796b8d967a0d2c")
    assert parse_blob_record(b"\x01" + json.dumps(ST_BLOB_B[:100]).encode()) is None
    assert parse_blob_record(b"\x01" + json.dumps(ST_BLOB_B + "0").encode()) is None
    assert parse_blob_record(b"\x01" + json.dumps("zz" + ST_BLOB_B[2:]).encode()) is None
    assert parse_blob_record(None) is None

    # --- 2. cipher chains from the known derived key (stdlib has no
    # argon2; the argon2 step itself was GPU-validated)
    key = vault_key(ST_PASSWORD_HASH)
    assert len(key) == 32
    pt = _gcm_open(key, bytes.fromhex(ST_IV_HEX), bytes.fromhex(ST_BLOB_B)[16:])
    assert pt == ST_PT_B, pt
    pt = _gcm_open(key, bytes.fromhex(ST_IV_HEX), bytes.fromhex(ST_BLOB_C)[16:])
    assert pt == ST_PT_C, pt
    assert _gcm_open(vault_key("00" * 32), bytes.fromhex(ST_IV_HEX),
                     bytes.fromhex(ST_BLOB_B)[16:]) is None

    # --- 2b. era A record parsing + PBKDF2/HMAC chain (from the known
    # argon2i hash; argon2 itself was GPU-validated)
    for value in (b"\x01" + ST_LS_SALT.encode(),
                  b"\x00" + ST_LS_SALT.encode("utf-16-le"),
                  ST_LS_SALT):
        assert parse_ls_salt(value) == ST_LS_SALT, value
    assert parse_ls_salt(b"\x01" + ST_LS_SALT[:-1].encode()) is None
    assert parse_ls_salt(b"\x02" + ST_LS_SALT.encode()) is None
    assert parse_ls_salt(None) is None

    persist = json.dumps({"encryptedSeed": json.dumps(ST_BLOB_A1),
                          "other": "{}"})
    a1 = parse_encrypted_seed(b"\x01" + persist.encode())
    assert a1 is not None
    assert a1["salt16_hex"] == ST_LS_SALT
    assert a1["ct"].hex() == ST_BLOB_A1[96:]
    # rejections: missing field, truncated, odd length, non-hex
    assert parse_encrypted_seed(b'\x01{"other": "{}"}') is None
    assert parse_encrypted_seed(b"\x01not json") is None
    bad = json.dumps({"encryptedSeed": json.dumps(ST_BLOB_A1[:100])})
    assert parse_encrypted_seed(bad) is None
    bad = json.dumps({"encryptedSeed": json.dumps(ST_BLOB_A1 + "0")})
    assert parse_encrypted_seed(bad) is None
    bad = json.dumps({"encryptedSeed": json.dumps("zz" + ST_BLOB_A1[2:])})
    assert parse_encrypted_seed(bad) is None

    # PBKDF2-HMAC-SHA512(utf8(argon2i-hex), salt16, 100000) -> macKey
    # -> HMAC-SHA256(macKey, salt16 || ct) == stored hmac (both blobs)
    for blob_hex in (ST_BLOB_A1, ST_BLOB_A2):
        salt16 = bytes.fromhex(blob_hex[:32])
        mac_hex = blob_hex[32:96]
        ct = bytes.fromhex(blob_hex[96:])
        dk = hashlib.pbkdf2_hmac("sha512", ST_ARGON2I_HASH.encode(),
                                 salt16, 100000, 32)
        mac = hmac.new(dk[16:32], salt16 + ct, hashlib.sha256).hexdigest()
        assert mac == mac_hex, blob_hex[:16]

    # --- 3b. era A hash lines match the GPU-cracked lines
    assert format_hash_a(ST_LS_SALT, a1["salt16_hex"], a1["hmac_hex"],
                         a1["ct"]) == ST_LINE_A1
    a2 = parse_encrypted_seed(json.dumps(
        {"encryptedSeed": json.dumps(ST_BLOB_A2)}))
    assert format_hash_a(ST_LS_SALT, a2["salt16_hex"], a2["hmac_hex"],
                         a2["ct"]) == ST_LINE_A2

    # --- grammar: $xverse-a$ls32$salt16_32$hmac64$ct64|96
    for line in (ST_LINE_A1, ST_LINE_A2):
        parts = line.split("$")
        assert parts[0] == "" and parts[1] == "xverse-a" and len(parts) == 6
        assert len(parts[2]) == 32 and len(parts[3]) == 32
        assert len(parts[4]) == 64
        assert len(parts[5]) in (64, 96)
        for f in parts[2:]:
            bytes.fromhex(f)

    # --- 3. hash lines from the fixture blobs match the GPU-cracked lines
    assert format_hash("b", ST_SALT_STR, ST_IV_HEX, b["ct32"]) == ST_LINE_B
    bc = parse_blob_record(json.dumps(ST_BLOB_C))
    assert format_hash("c", ST_SALT_STR, ST_IV_HEX, bc["ct32"]) == ST_LINE_C

    # --- grammar: $xverse$<b|c>$salt64$iv32$ct64
    for line, era in ((ST_LINE_B, "b"), (ST_LINE_C, "c")):
        parts = line.split("$")
        assert parts[0] == "" and parts[1] == "xverse" and len(parts) == 6
        assert parts[2] == era
        assert len(parts[3]) == 64 and len(parts[4]) == 32
        assert len(parts[5]) == 64
        bytes.fromhex(parts[3]); bytes.fromhex(parts[4])
        bytes.fromhex(parts[5])

    # --- 4. end-to-end through a synthetic LevelDB .log
    with tempfile.TemporaryDirectory() as td:
        _write_log(os.path.join(td, "000003.log"), [
            (_key(b"passwordSalt"), b"\x01" + json.dumps(ST_SALT_STR).encode()),
            (_key(b"encryptedKey"), b"\x01" + json.dumps(ST_BLOB_B).encode()),
            (_key(b"vault::passwordSalt"),
             b"\x01" + json.dumps(ST_SALT_STR).encode()),
            (_key(b"vault::encryptionVault"),
             b"\x01" + json.dumps(ST_BLOB_C).encode()),
            (_key(b"other"), b'\x01{"foo": 1}'),
        ])
        res = scan_dir(td)
    assert res["note"] is None, res
    hashes = sorted(e["hash"] for e in res["hashes"])
    assert hashes == sorted([ST_LINE_B, ST_LINE_C]), res
    assert all(e["mode"] == MODE for e in res["hashes"])

    # salt without blob -> warn note, no lines
    with tempfile.TemporaryDirectory() as td:
        _write_log(os.path.join(td, "000003.log"),
                   [(_key(b"passwordSalt"),
                     b"\x01" + json.dumps(ST_SALT_STR).encode())])
        res = scan_dir(td)
    assert res["hashes"] == [] and "no encryptedKey" in res["note"], res

    # --- 5b. era A end-to-end: LES (persist:walletState) + DOM localStorage
    # (salt) in the profile layout, plus era-b/c records alongside
    with tempfile.TemporaryDirectory() as td:
        les = os.path.join(td, "Default", LES_NAME, XVERSE_EXTENSION_ID)
        dom = os.path.join(td, "Default", DOM_LS_DIRNAME)
        os.makedirs(les)
        os.makedirs(dom)
        _write_log(os.path.join(les, "000003.log"), [
            (_key(b"persist:walletState"), b"\x01" + persist.encode()),
            (_key(b"passwordSalt"), b"\x01" + json.dumps(ST_SALT_STR).encode()),
            (_key(b"encryptedKey"), b"\x01" + json.dumps(ST_BLOB_B).encode()),
        ])
        _write_log(os.path.join(dom, "000003.log"), [
            (b"_chrome-extension://" + XVERSE_EXTENSION_ID.encode()
             + b"\x00\x01salt", b"\x01" + ST_LS_SALT.encode()),
        ])
        res = scan_dir(les)
    hashes = sorted(e["hash"] for e in res["hashes"])
    assert hashes == sorted([ST_LINE_A1, ST_LINE_B]), res
    modes = sorted(e["mode"] for e in res["hashes"])
    assert modes == sorted([MODE, MODE_A]), res

    # era A blob without the DOM salt -> warn note, no era-a line
    with tempfile.TemporaryDirectory() as td:
        les = os.path.join(td, "Default", LES_NAME, XVERSE_EXTENSION_ID)
        os.makedirs(les)
        _write_log(os.path.join(les, "000003.log"),
                   [(_key(b"persist:walletState"), b"\x01" + persist.encode())])
        res = scan_dir(les)
    assert res["hashes"] == [] and "no localStorage salt" in res["note"], res

    # no Xverse records at all -> no hash, note
    with tempfile.TemporaryDirectory() as td:
        _write_log(os.path.join(td, "000003.log"),
                   [(b"other-app", b'\x01{"data":{"foo":1}}')])
        res = scan_dir(td)
    assert res["hashes"] == [] and res["note"], res

    print("self-test OK")


# ---------------------------------------------------------------- main

def _targets_from_path(path):
    if os.path.isdir(path):
        return [{"path": path, "where": "Xverse Wallet"}]
    return None


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="Extract $xverse$ hashes from the Xverse Wallet "
                    "browser extension. Offline, read-only.")
    parser.add_argument("--dir", metavar="PATH",
                        help="scan a specific extension storage directory "
                             "instead of the interactive menu")
    parser.add_argument("--all", action="store_true",
                        help="extract from every detected installation "
                             "without prompting")
    parser.add_argument("--output", metavar="FILE", default=None,
                        help="where to save the era-b/c result (default: "
                             + OUTPUT_NAME + " next to the script; "
                             "legacy era-a lines always go to "
                             + OUTPUT_NAME_A + ")")
    parser.add_argument("--self-test", action="store_true",
                        help="verify the output format and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0

    targets = None
    if args.dir:
        targets = _targets_from_path(args.dir)
        if targets is None:
            print("error: no Xverse Wallet storage found at %s" % args.dir,
                  file=sys.stderr)
            return 1
    elif args.all:
        targets = find_stores()
        if not targets:
            print("No Xverse Wallet installations detected on this machine.")
            return 1
    else:
        mode = arrow_select("Select mode:", [
            ("Auto", "(recommended)"),
            ("Manual", None),
        ])
        if mode == 1:
            path = manual_pick_path()
            if not path:
                print("No folder selected.")
                return 1
            targets = _targets_from_path(path)
            if targets is None:
                print("error: no Xverse Wallet storage found at %s" % path,
                      file=sys.stderr)
                return 1
        else:
            targets = find_stores()
            if not targets:
                print("No Xverse Wallet installations detected on this "
                      "machine.")
                print("If the extension lives in a portable or unusual "
                      "browser, run again and choose Manual — or contact us.")
                return 1
            options = [("All storage found", None)] + \
                      [("%s (%s)" % (s["where"], s["path"]), None)
                       for s in targets]
            choice = arrow_select("Select storage:", options, default=0)
            if choice != 0:
                targets = [targets[choice - 1]]

    all_hashes = []
    notes = []
    print()
    scan_rows = 1
    for t in targets:
        with Spinner("Scanning %s" % t["path"]) as sp:
            scan_rows += sp.rows
            result = scan_dir(t["path"])
        for e in result["hashes"]:
            all_hashes.append((t["path"], e["where"], e["hash"], e["mode"]))
        if result["note"]:
            notes.append(result["note"])

    if sys.stdout.isatty():
        sys.stdout.write("\x1b[%dA" % scan_rows + "\x1b[J")
    for n in notes:
        print("note: %s" % n, file=sys.stderr)

    if not all_hashes:
        print("\nNo crackable hash could be extracted from the scanned "
              "storage.")
        print("If the wallet is password-protected and extraction still "
              "fails, contact us — we will guide you through a manual "
              "extraction.")
        return 1

    lines = []
    lines_a = []
    box = ["Successfully extracted!", ""]
    seen = set()
    for path, where, h, mode in all_hashes:
        if h in seen:
            continue
        seen.add(h)
        box.append("[Directory] %s (%s)" % (path, where))
        _hl = "[Hash] %s" % h
        if (not sys.stdout.isatty()) \
                or len(_hl) <= 3 * (shutil.get_terminal_size().columns - 2):
            box.append(_hl)
        else:
            box.append("[Hash] (too long to display - in the saved file)")
        box.append("[Mode] %d" % mode)
        box.append("")
        (lines_a if mode == MODE_A else lines).append(h)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    outputs = []
    if lines:
        out_bc = args.output or os.path.join(script_dir, OUTPUT_NAME)
        try:
            with open(out_bc, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except OSError:
            out_bc = os.path.join(os.getcwd(), OUTPUT_NAME)
            with open(out_bc, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        outputs.append(out_bc)
    if lines_a:
        out_a = os.path.join(script_dir, OUTPUT_NAME_A)
        try:
            with open(out_a, "w", encoding="utf-8") as f:
                f.write("\n".join(lines_a) + "\n")
        except OSError:
            out_a = os.path.join(os.getcwd(), OUTPUT_NAME_A)
            with open(out_a, "w", encoding="utf-8") as f:
                f.write("\n".join(lines_a) + "\n")
        outputs.append(out_a)

    for o in outputs:
        box.append("Saved to %s" % o)
    if lines and lines_a:
        box.append("")
        box.append("Note: era-a (legacy) and era-b/c lines are different "
                   "hashcat modes - send both files, we handle the split.")
    print_box(box)
    return 0


if __name__ == "__main__":
    sys.exit(main())
