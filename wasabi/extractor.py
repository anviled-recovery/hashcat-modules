#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wasabi extractor — emits $wasabi$ hashes (custom hashcat module 90020).

Wasabi Wallet (zkSNACKs, 1.x and 2.x alike) stores one JSON file per
wallet in `WalletWasabi\Client\Wallets\<name>.json`. The `EncryptedSecret`
field is a standard BIP-0038 non-EC-multiplied encrypted key:

    payload (39 bytes, Base58Check, starts with "6P"):
        0x01 0x42 | flagbyte 0xe0 | addresshash (4) | ct (32)

        addresshash = SHA256(SHA256(ascii(P2PKH address)))[0:4]  (= scrypt salt)
        key         = scrypt(UTF-8(NFC(password)), addresshash,
                             N=16384, r=8, p=8, dkLen=64)
        ct          = AES-256-ECB(privkey XOR derivedhalf1, key=derivedhalf2)

Verification inside hashcat: secp256k1 privkey -> compressed pubkey ->
HASH160 -> Base58 address -> the 4-byte addresshash must match. The hash
is the BIP38 string itself — 39 bytes of verification material; after a
successful crack only that single private key is exposed, the rest of
the wallet file never leaves the machine.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import sys
import tempfile
import threading

MODE = 90020
OUTPUT_NAME = "wasabi-hash.txt"

BIP38_RE = re.compile(r"^6P[1-9A-HJ-NP-Za-km-z]{50,60}$")


# ------------------------------------------------------------------ hashing

def _b58check_decode(s):
    raw = b58decode(s)
    if len(raw) < 5:
        raise ValueError("too short")
    body, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != chk:
        raise ValueError("bad Base58Check checksum")
    return body


def parse_encrypted_secret(value):
    """Validate an EncryptedSecret BIP38 string -> the string itself."""
    if not isinstance(value, str) or not BIP38_RE.match(value):
        raise ValueError("not a BIP38 '6P' string")
    body = _b58check_decode(value)
    if len(body) != 39 or body[0] != 0x01 or body[1] != 0x42:
        raise ValueError("not a BIP38 non-EC-multiplied payload")
    if body[2] & 0x1F != 0:
        raise ValueError("unsupported BIP38 flagbyte")
    return value


def format_hash(b58str):
    return "$wasabi$%s" % b58str


# --------------------------------------------------------------- extraction

def scan_file(path):
    """-> {'hashes': [...], 'note': str|None} for one wallet JSON file."""
    try:
        with open(path, "rb") as f:
            obj = json.loads(f.read(4 << 20).decode("utf-8", "replace"))
    except (OSError, ValueError) as e:
        return {"hashes": [], "note": "%s: cannot parse (%s)" % (path, e)}
    if not isinstance(obj, dict):
        return {"hashes": [], "note": "%s: not a Wasabi wallet file" % path}

    enc = obj.get("EncryptedSecret")
    if not enc:
        return {"hashes": [], "note": "%s: watch-only wallet (no "
                                      "EncryptedSecret) — nothing to crack"
                                      % path}
    try:
        b58str = parse_encrypted_secret(enc)
    except ValueError as e:
        return {"hashes": [], "note": "%s: %s" % (path, e)}

    name = obj.get("WalletName") or os.path.splitext(os.path.basename(path))[0]
    return {"hashes": [{"hash": format_hash(b58str), "mode": MODE,
                        "where": "Wasabi wallet (%s)" % name}],
            "note": None}


# ---------------------------------------------------------------- discovery

def candidate_roots():
    system = platform.system()
    home = os.path.expanduser("~")
    if system == "Windows":
        roots = [
            os.path.join(os.environ.get(
                "APPDATA", os.path.join(home, "AppData", "Roaming")),
                "WalletWasabi", "Client", "Wallets"),
            os.path.join(os.environ.get(
                "LOCALAPPDATA", os.path.join(home, "AppData", "Local")),
                "WalletWasabi", "Client", "Wallets"),
        ]
    else:
        roots = [os.path.join(home, ".walletwasabi", "client", "wallets")]
    return [r for r in roots if os.path.isdir(r)]


def find_wallet_files():
    found = []
    seen = set()
    for root in candidate_roots():
        try:
            names = sorted(os.listdir(root))
        except OSError:
            continue
        for name in names:
            p = os.path.join(root, name)
            if os.path.isfile(p) and name.lower().endswith(".json") \
                    and p not in seen:
                seen.add(p)
                found.append(p)
    return found


# ------------------------------------------------------------------- base58

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_MAP = {c: i for i, c in enumerate(_B58_ALPHABET)}


def b58decode(s):
    """Decode a base58 (Bitcoin alphabet) string into bytes."""
    num = 0
    for c in s:
        num = num * 58 + _B58_MAP[c]
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def b58encode(b):
    """Encode bytes into a base58 (Bitcoin alphabet) string."""
    num = int.from_bytes(b, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = _B58_ALPHABET[rem] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + (out or "")




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


def format_wallet_option(f):
    return os.path.basename(f["dir"].rstrip("/\\"))


def interactive_auto(files):
    """Picker: wallet(s) to extract from. Returns the chosen entries."""
    options = [("All wallets found", None)] + \
              [(format_wallet_option(f), None) for f in files]
    choice = arrow_select("Select wallet:", options, default=0)
    if choice == 0:
        return files
    return [files[choice - 1]]


def manual_pick_path():
    """Native file-picker dialog (tkinter); falls back to typed input.
    Accepts either a .wallet.aes file or a wallet directory."""
    path = None
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        path = filedialog.askopenfilename(
            title="Select the MultiBit HD wallet file (mbhd.wallet.aes)")
        root.destroy()
    except Exception:
        path = None
    if not path:
        try:
            raw = input("Enter the wallet file (or folder) path: ").strip().strip('"')
        except EOFError:
            raw = ""
        path = raw or None
    return path




# ---------------------------------------------------------------- self-test

# ----------------------------------------------------------- pure-python AES
# AES-256-CBC encrypt+decrypt, used ONLY by --self-test and --make-vector.
# stdlib has no AES and we ship zero third-party dependencies.
# Correctness is pinned by the FIPS-197 known-answer test in self_test().

_SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)

_INV_SBOX = (
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
)

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _aes_expand_key(key):
    """Rijndael key schedule for a 16/24/32-byte key (AES-128/192/256).
    Returns (nr+1) round keys of 16 bytes."""
    if len(key) not in (16, 24, 32):
        raise ValueError("key must be 16, 24 or 32 bytes")
    nk, nr = len(key) // 4, len(key) // 4 + 6
    w = [list(key[i * 4:(i + 1) * 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = w[i - 1][:]
        if i % nk == 0:
            # RotWord(t) = [t1,t2,t3,t0]; SubWord each; Rcon on first byte.
            t = [_SBOX[t[1]] ^ _RCON[i // nk - 1], _SBOX[t[2]],
                 _SBOX[t[3]], _SBOX[t[0]]]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[t[0]], _SBOX[t[1]], _SBOX[t[2]], _SBOX[t[3]]]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return [sum(w[i * 4:(i + 1) * 4], []) for i in range(nr + 1)]


def _xtime(a):
    return ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xFF


def _aes_encrypt_block(round_keys, block):
    nr = len(round_keys) - 1
    s = [block[i] ^ round_keys[0][i] for i in range(16)]

    def sub_bytes():
        for i in range(16):
            s[i] = _SBOX[s[i]]

    def shift_rows():
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]

    def mix_columns():
        for c in range(4):
            i = c * 4
            a, b, cc, d = s[i], s[i + 1], s[i + 2], s[i + 3]
            s[i] = _xtime(a) ^ _xtime(b) ^ b ^ cc ^ d
            s[i + 1] = a ^ _xtime(b) ^ _xtime(cc) ^ cc ^ d
            s[i + 2] = a ^ b ^ _xtime(cc) ^ _xtime(d) ^ d
            s[i + 3] = _xtime(a) ^ a ^ b ^ cc ^ _xtime(d)

    for rnd in range(1, nr):
        sub_bytes()
        shift_rows()
        mix_columns()
        for i in range(16):
            s[i] ^= round_keys[rnd][i]
    sub_bytes()
    shift_rows()
    for i in range(16):
        s[i] ^= round_keys[nr][i]
    return bytes(s)


def _aes_decrypt_block(round_keys, block):
    nr = len(round_keys) - 1
    s = [block[i] ^ round_keys[nr][i] for i in range(16)]

    def inv_sub_bytes():
        for i in range(16):
            s[i] = _INV_SBOX[s[i]]

    def inv_shift_rows():
        s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]

    def inv_mix_columns():
        def mul(a, b):
            p = 0
            for _ in range(8):
                if b & 1:
                    p ^= a
                carry = a & 0x80
                a = (a << 1) & 0xFF
                if carry:
                    a ^= 0x1B
                b >>= 1
            return p
        for c in range(4):
            i = c * 4
            a, b, cc, d = s[i], s[i + 1], s[i + 2], s[i + 3]
            s[i] = mul(a, 14) ^ mul(b, 11) ^ mul(cc, 13) ^ mul(d, 9)
            s[i + 1] = mul(a, 9) ^ mul(b, 14) ^ mul(cc, 11) ^ mul(d, 13)
            s[i + 2] = mul(a, 13) ^ mul(b, 9) ^ mul(cc, 14) ^ mul(d, 11)
            s[i + 3] = mul(a, 11) ^ mul(b, 13) ^ mul(cc, 9) ^ mul(d, 14)

    for rnd in range(nr - 1, 0, -1):
        inv_shift_rows()
        inv_sub_bytes()
        for i in range(16):
            s[i] ^= round_keys[rnd][i]
        inv_mix_columns()
    inv_shift_rows()
    inv_sub_bytes()
    for i in range(16):
        s[i] ^= round_keys[0][i]
    return bytes(s)


def _pkcs7_pad(data):
    padlen = 16 - (len(data) % 16)
    return data + bytes([padlen]) * padlen


def _pkcs7_unpad(data):
    if not data or len(data) % 16:
        raise ValueError("invalid padding")
    padlen = data[-1]
    if padlen < 1 or padlen > 16 or data[-padlen:] != bytes([padlen]) * padlen:
        raise ValueError("invalid padding")
    return data[:-padlen]


def aes256_cbc_encrypt(key, iv, plaintext):
    """AES-256-CBC + PKCS7. Returns IV || ciphertext."""
    round_keys = _aes_expand_key(key)
    data = _pkcs7_pad(plaintext)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = bytes(x ^ y for x, y in zip(data[i:i + 16], prev))
        prev = _aes_encrypt_block(round_keys, block)
        out += prev
    return bytes(iv) + bytes(out)


def aes256_cbc_decrypt(key, blob):
    """Inverse of aes256_cbc_encrypt."""
    if len(blob) < 32 or len(blob) % 16:
        raise ValueError("bad blob length")
    iv, ct = blob[:16], blob[16:]
    round_keys = _aes_expand_key(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ct), 16):
        block = ct[i:i + 16]
        out += bytes(x ^ y for x, y in zip(_aes_decrypt_block(round_keys, block), prev))
        prev = block
    return _pkcs7_unpad(bytes(out))




# ------------------------------------------------------------- EC helpers
# pure-python secp256k1 (self-test only)

_P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_G_POINT = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _ec_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] != q[1] or p[1] == 0):
        return None
    if p == q:
        lam = (3 * p[0] * p[0]) * pow(2 * p[1], _P_FIELD - 2, _P_FIELD) % _P_FIELD
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], _P_FIELD - 2, _P_FIELD) % _P_FIELD
    x = (lam * lam - p[0] - q[0]) % _P_FIELD
    return (x, (lam * (p[0] - x) - p[1]) % _P_FIELD)


def _ec_mul(k):
    r = None
    b = _G_POINT
    while k:
        if k & 1:
            r = _ec_add(r, b)
        b = _ec_add(b, b)
        k >>= 1
    return r


def _hash160(data):
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _b58check_encode(prefix, payload):
    raw = bytes([prefix]) + payload
    chk = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    return b58encode(raw + chk)


def _privkey_to_address(privkey):
    x, y = _ec_mul(privkey)
    pub = bytes([2 | (y & 1)]) + x.to_bytes(32, "big")
    return _b58check_encode(0x00, _hash160(pub))


def _bip38_decrypt(b58str, password):
    body = _b58check_decode(b58str)
    flag, addresshash, ct = body[2], body[3:7], body[7:39]
    out = hashlib.scrypt(password.encode("utf-8"), salt=addresshash,
                         n=16384, r=8, p=8, dklen=64, maxmem=128 * 1024 * 1024)
    dh1, dh2 = out[:32], out[32:]
    rk = _aes_expand_key(dh2)
    h1 = bytes(a ^ b for a, b in zip(_aes_decrypt_block(rk, ct[:16]), dh1[:16]))
    h2 = bytes(a ^ b for a, b in zip(_aes_decrypt_block(rk, ct[16:]), dh1[16:]))
    return int.from_bytes(h1 + h2, "big"), addresshash


def self_test():
    # FIPS-197 AES-256 known-answer test
    rk = _aes_expand_key(bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
    ct = _aes_encrypt_block(rk, bytes.fromhex("00112233445566778899aabbccddeeff"))
    assert ct.hex() == "8ea2b7ca516745bfeafc49904b496089", ct.hex()
    assert _aes_decrypt_block(rk, ct).hex() == "00112233445566778899aabbccddeeff"

    # official BIP-0038 non-EC-multiplied test vectors
    for pw, b58str, want_addr in (
        ("TestingOneTwoThree",
         "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
         "164MQi977u9GUteHr4EPH27VkkdxmfCvGW"),
        ("Satoshi",
         "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
         "1HmPbwsvG5qJ3KJfxzsZRZWhbm1xBMuS8B"),
    ):
        assert parse_encrypted_secret(b58str) == b58str
        priv, addrhash = _bip38_decrypt(b58str, pw)
        addr = _privkey_to_address(priv)
        assert addr == want_addr, addr
        ah = hashlib.sha256(hashlib.sha256(addr.encode()).digest()).digest()[:4]
        assert ah == addrhash

    # wrong password must NOT reproduce the addresshash
    priv, addrhash = _bip38_decrypt(
        "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo", "nope")
    addr = _privkey_to_address(priv)
    ah = hashlib.sha256(hashlib.sha256(addr.encode()).digest()).digest()[:4]
    assert ah != addrhash

    # scan_file round-trip
    obj = {"EncryptedSecret":
           "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
           "ChainCode": "aa" * 32, "ExtPubKey": "xpub6...",
           "WalletName": "Test Wasabi"}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False,
                                     mode="w", encoding="utf-8") as f:
        json.dump(obj, f)
        tmp = f.name
    try:
        res = scan_file(tmp)
    finally:
        os.unlink(tmp)
    assert res["note"] is None and len(res["hashes"]) == 1, res
    h = res["hashes"][0]["hash"]
    assert h == "$wasabi$6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo", h
    assert "Test Wasabi" in res["hashes"][0]["where"]
    assert re.fullmatch(r"\$wasabi\$6P[1-9A-HJ-NP-Za-km-z]{50,60}", h)

    # watch-only -> note, no hash
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False,
                                     mode="w", encoding="utf-8") as f:
        json.dump({"ExtPubKey": "xpub6..."}, f)
        tmp = f.name
    try:
        res = scan_file(tmp)
    finally:
        os.unlink(tmp)
    assert res["hashes"] == [] and "watch-only" in res["note"]

    # corrupted checksum and garbage are rejected
    for bad in ({"EncryptedSecret":
                 "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUep"},
                {"EncryptedSecret": "not-a-key"},
                {"EncryptedSecret": 12345}):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False,
                                         mode="w", encoding="utf-8") as f:
            json.dump(bad, f)
            tmp = f.name
        try:
            res = scan_file(tmp)
        finally:
            os.unlink(tmp)
        assert res["hashes"] == [] and res["note"], bad

    print("self-test OK")


# ---------------------------------------------------------------- main

def _targets_from_path(path):
    if os.path.isfile(path):
        return [path]
    if os.path.isdir(path):
        found = []
        try:
            names = sorted(os.listdir(path))
        except OSError:
            names = []
        for name in names:
            p = os.path.join(path, name)
            if os.path.isfile(p) and name.lower().endswith(".json"):
                found.append(p)
        return found or None
    return None


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="Extract $wasabi$ hashes from Wasabi Wallet files. "
                    "Offline, read-only.")
    parser.add_argument("--dir", metavar="PATH",
                        help="scan a specific wallet file or directory "
                             "instead of the interactive menu")
    parser.add_argument("--all", action="store_true",
                        help="extract from every detected wallet without "
                             "prompting")
    parser.add_argument("--output", metavar="FILE", default=None,
                        help="where to save the result (default: "
                             + OUTPUT_NAME + " next to the script)")
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
            print("error: no Wasabi wallet found at %s" % args.dir,
                  file=sys.stderr)
            return 1
    elif args.all:
        targets = find_wallet_files()
        if not targets:
            print("No Wasabi installations detected on this machine.")
            return 1
    else:
        mode = arrow_select("Select mode:", [
            ("Auto", "(recommended)"),
            ("Manual", None),
        ])
        if mode == 1:
            path = manual_pick_path()
            if not path:
                print("No file selected.")
                return 1
            targets = _targets_from_path(path)
            if targets is None:
                print("error: no Wasabi wallet found at %s" % path,
                      file=sys.stderr)
                return 1
        else:
            targets = find_wallet_files()
            if not targets:
                print("No Wasabi installations detected on this machine.")
                print("If Wasabi lives in a custom location, run again "
                      "and choose Manual — or contact us.")
                return 1
            options = [("All wallets found", None)] + \
                      [(os.path.basename(t), None) for t in targets]
            choice = arrow_select("Select wallet:", options, default=0)
            if choice != 0:
                targets = [targets[choice - 1]]

    all_hashes = []
    notes = []
    print()
    scan_rows = 1
    for path in targets:
        with Spinner("Scanning %s" % path) as sp:
            scan_rows += sp.rows
            result = scan_file(path)
        for e in result["hashes"]:
            all_hashes.append((path, e["where"], e["hash"], e["mode"]))
        if result["note"]:
            notes.append(result["note"])

    if sys.stdout.isatty():
        sys.stdout.write("\x1b[%dA" % scan_rows + "\x1b[J")
    for n in notes:
        print("note: %s" % n, file=sys.stderr)

    if not all_hashes:
        print("\nNo crackable hash could be extracted from the scanned "
              "wallet files.")
        print("If the wallet is password-protected and extraction still "
              "fails, contact us — we will guide you through a manual "
              "extraction.")
        return 1

    lines = []
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
        lines.append(h)

    output = args.output or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), OUTPUT_NAME)
    try:
        with open(output, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError:
        output = os.path.join(os.getcwd(), OUTPUT_NAME)
        with open(output, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    box.append("Saved to %s" % output)
    print_box(box)
    return 0


if __name__ == "__main__":
    sys.exit(main())
