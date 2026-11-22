# hashcat-modules

Custom hashcat modules for wallet formats whose hash line contains the **entire encrypted secret** — not just a verification sample. These modules are not part of the [Anviled recovery service](https://github.com/anviled-recovery/extraction-tools), which accepts only seedless hashes.

They are published for **local password recovery on your own files**.

## Security

A hash produced by these modules is the complete encrypted vault. Before the password is cracked it reveals nothing; **after a successful crack it reveals the whole seed or private key to whoever holds the line**. That is why the service does not accept such hashes, and why you should never send one to any third party. Extract and crack on your own hardware only.

## Available modules

| Module | Wallet | Reason it is here |
| --- | --- | --- |
| `90020` `$wasabi$` | [Wasabi (BIP38)](wasabi/) | The line is the whole BIP38 string — the full encrypted private key. |
| `90037` `$xverse-a$` | [Xverse legacy era A](xverse-era-a/) | The verifier needs the complete ciphertext of the seed entropy, so the line is the full encrypted mnemonic. |

Each directory contains the module source (`.c` + `.cl`), a matching extractor, and its own README.md.

## Getting started

1. Download this repository using **Code → Download ZIP**.
2. Build hashcat **v8.0.0 or newer** from source, then copy the module in:

   ```
   cp <wallet>/module_900XX.c  hashcat/src/modules/
   cp <wallet>/m900XX-pure.cl  hashcat/OpenCL/
   cd hashcat && make modules
   ```

3. Open the directory for your wallet and follow its README.md to run the extractor. It writes a `.txt` hash file next to itself.
4. Crack the hash file locally:

   ```
   ./hashcat -m 900XX hash-file.txt your-dictionary.txt
   ```

Windows, macOS and Linux are supported for the extractors (Python 3.8+, no third-party packages). GPU or CPU for hashcat.

## Using the extracted hash

These hashes are for local use. Do not submit them to Anviled or any other recovery service — after a successful crack, whoever holds the hash owns the wallet.

If your wallet is not listed here, check the [service extractors](https://github.com/anviled-recovery/extraction-tools): most formats have a seedless variant that a service can crack safely.

## Contact

Email: [recovery@anviled.io](mailto:recovery@anviled.io)

Alternative contact channels and OpenPGP instructions are available on [anviled.io](https://anviled.io/#contacts).

## License

The original code in this repository is licensed under the [MIT License](LICENSE). Adapted and third-party components retain their applicable license and copyright notices.
