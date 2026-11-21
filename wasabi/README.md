# <img width="28" height="28" alt="wasabi_logo" src="https://avatars.githubusercontent.com/u/38204679?v=4" /> Wasabi extractor

Extracts a hash from a local Wasabi Wallet (`WalletWasabi\Client\Wallets\*.json`). Cracked with the custom hashcat module in this repository (**local cracking only** — the anviled recovery service does not accept Wasabi hashes, because after a successful crack the line exposes the full private key).

| Mode | Format | Meaning |
| --- | --- | --- |
| `90020` | `$wasabi$<BIP38 string>` | **Direct storage**: the 39-byte BIP38 payload is the entire encrypted private key — verification is an address-hash recompute, but after a crack the key is fully exposed |

## How Wasabi protects your wallet

The wallet's master key is encrypted as a standard **BIP-0038** (non-EC-multiplied) secret: **scrypt** (N=16384, r=8, p=8 — your password, salted with a 4-byte hash of the wallet's own address) derives 64 bytes; the second half keys **AES-256-ECB**, which encrypts the private key XORed with the first half.

Verification is baked into the format: after decryption, the candidate private key must reproduce the address the 4-byte `addresshash` came from (secp256k1 → HASH160 → Base58 → double-SHA256). The same scheme protects Wasabi 1.x and 2.x — one hash format covers every version.

The hash is just the BIP38 string (`6P…`, 58 characters): after a successful crack only that single private key is exposed. The rest of the wallet file (chain code, public keys, history) never leaves your machine.

## What it does

- Finds Wasabi wallet files automatically (`%APPDATA%\WalletWasabi\Client\Wallets`, `~/.walletwasabi/client/wallets`), one hash per wallet.
- Skips watch-only wallets (they have no encrypted secret).
- Interactive menu: no command-line knowledge needed.
- Reads wallet files **read-only** and never modifies them. Works fully offline and transmits nothing.
- Windows, macOS or Linux.

## Requirements

- Python 3.8 or newer ([python.org/downloads](https://www.python.org/downloads/)). On Windows, enable **"Add python.exe to PATH"** during installation.

## Usage

1. Close Wasabi.
2. Open a terminal in this directory and run:

   ```
   python extractor.py
   ```

3. Choose a mode with the up/down arrow keys and press Enter:

   ```
   Select mode: (up/down, Enter)
   > Auto (recommended)
     Manual
   ```

4. **Auto**: the extractor lists the detected wallets. **Manual**: a file-selection window opens — pick a wallet `.json` file or its folder.
5. The hash line(s) are saved to `wasabi-hash.txt` next to the script. In the terminal a hash is printed when it fits in up to three lines - longer ones are copied from the saved file. Each hash is labeled with its `[Mode]` (`90020`).
6. Crack it **locally** with the module in this folder (build and run instructions are in the [repo README](../README.md)). Do not submit the line to any recovery service — after a successful crack, whoever holds it owns the key.

## Troubleshooting

- **"No Wasabi installations detected"** — Wasabi must have been used on this machine. If it lives in a custom location, run again and choose **Manual**.
- **"watch-only wallet"** — that wallet file has no `EncryptedSecret` (no password was set); nothing to crack.

## Support flags

Usually not needed — for guided support sessions only:

| Flag | Effect |
| --- | --- |
| `--dir PATH` | Scan a specific wallet file or directory, skip the menu |
| `--all` | Extract from every detected wallet without prompting |
| `--output FILE` | Save the result to a custom file |
| `--self-test` | Verify the output format |

## Security

Never send the wallet file or the hash line to anyone: the hash is the 39-byte BIP38 payload, and after a successful crack it exposes the private key itself. Extract and crack on your own machine only.
