# Xverse legacy era A (mode 90037)

Xverse wallets created with extension versions 0.6 – 0.21 (2021-2022, the pre-SeedVault era). Their vault is:

```
argon2i(password, utf8(localStorage salt hex-string), t=3, m=65536, p=4, 48)
-> hex -> PBKDF2-HMAC-SHA512(salt16, 100000) -> macKey
blob = hex(salt16 || HMAC-SHA256(macKey, salt16 || ct) || ct)
```

The stored HMAC is the only verifier, and computing it requires the **complete** ciphertext — which is the full bip39 entropy of the mnemonic. So the `$xverse-a$` hash line is the entire encrypted seed, and after a successful crack it is fully exposed. That is why this mode lives here and not in the recovery service. (The newer Xverse eras B and C *are* seedless and are supported by the service as mode 90036.)

## Files

- `module_90037.c`, `m90037-pure.cl` — the hashcat module (hashcat v8.0.0+ required, argon2 framework).
- `extractor.py` — the Xverse extractor (this copy still emits the legacy `$xverse-a$` lines into `xverse-a-hash.txt`; it also emits the seedless `$xverse$` b/c lines into `xverse-hash.txt`, which the service accepts).

## Usage

1. Build the module into hashcat (see the [repo README](../README.md)).
2. Run `python extractor.py` on the machine with the wallet (see the [service README](https://github.com/anviled-recovery/extraction-tools/tree/main/wallets/XVerse) for the full guide).
3. Crack the `xverse-a-hash.txt` file **locally**:

   ```
   ./hashcat -m 90037 xverse-a-hash.txt your-dictionary.txt
   ```

Do not submit the `xverse-a-hash.txt` file to any recovery service: after a successful crack, whoever holds it owns the mnemonic.
