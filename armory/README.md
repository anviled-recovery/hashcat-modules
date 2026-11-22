# <img width="28" height="28" alt="armory_logo" src="https://btcarmory.com/favicon.ico" /> Armory extractor

Extracts a hash from a local Armory wallet (`armory_*.wallet`). Cracked with the custom hashcat module in this repository (**local cracking only** — the anviled recovery service does not accept Armory hashes, because after a successful crack the line exposes the private key itself).

| Mode | Format | Meaning |
| --- | --- | --- |
| `90021` | `$armory$<mem>$<iter>$<salt>$<addr>$<iv>$<key>` | **Direct storage**: the line carries the full encrypted private key (32 bytes) plus its address as the verifier — after a crack the key is fully exposed |

## How Armory protects your wallet

Every Armory version (0.8x through the goatpig fork) uses the same binary wallet format. The spending password goes through **ROMix** — a memory-hard SHA-512 KDF (memory and iteration count are tuned per wallet and stored in the file header) — and the resulting 32-byte key encrypts each private key with **AES-256-CFB** under a per-address IV.

Verification is baked in: the decrypted private key must reproduce the public key stored in the same address entry (secp256k1 point multiplication). The hash carries only what the check needs — salt, KDF params, one address hash, its IV and its encrypted key — so after a successful crack only that one key is exposed; the chain code and the rest of the wallet stay with you.

## What it does

- Finds Armory wallets automatically (`%APPDATA%\Armory`, `~/Library/Application Support/Armory`, `~/.armory`), including backups (`armory_*_backup.wallet`).
- Skips watching-only and unencrypted wallets automatically.
- Interactive menu: no command-line knowledge needed.
- Reads wallet files **read-only** and never modifies them. Works fully offline and transmits nothing.
- Windows, macOS or Linux.

## Requirements

- Python 3.8 or newer ([python.org/downloads](https://www.python.org/downloads/)). On Windows, enable **"Add python.exe to PATH"** during installation.

## Usage

1. Close Armory.
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

4. **Auto**: the extractor lists the detected wallets. **Manual**: a file-selection window opens — pick an `armory_*.wallet` file or its folder.
5. The hash line(s) are saved to `armory-hash.txt` next to the script. In the terminal a hash is printed when it fits in up to three lines - longer ones are copied from the saved file. Each hash is labeled with its `[Mode]` (`90021`).
6. Crack it **locally** with the module in this folder (build and run instructions are in the [repo README](../README.md)). Do not submit the line to any recovery service — after a successful crack, whoever holds it owns the key.

## Troubleshooting

- **"No Armory installations detected"** — Armory must have been used on this machine. If it lives in a custom location (`--datadir`), run again and choose **Manual**.
- **"watching-only wallet"** — that file has no encrypted keys; nothing to crack.
- **"wallet is not password-protected"** — that wallet has no spending password set; nothing to crack.
- **"no encrypted private key found"** — the wallet has a password but this file's addresses are all plaintext (unusual); contact us.

## Support flags

Usually not needed — for guided support sessions only:

| Flag | Effect |
| --- | --- |
| `--dir PATH` | Scan a specific wallet file or directory, skip the menu |
| `--all` | Extract from every detected wallet without prompting |
| `--output FILE` | Save the result to a custom file |
| `--self-test` | Verify the output format |
