# hashcat-modules

Custom hashcat modules that were **dropped from the [anviled recovery service](https://github.com/anviled-recovery/extraction-tools)** because they break its core safety invariant:

> After a successful crack, the hash line must reveal **nothing** beyond "the password is correct". The modules in this attic crack formats whose hash line contains the **entire encrypted secret** — so once the password falls, the full private key/seed falls with it.

That is a *direct-storage* hash, and the service does not accept those: a client who submits one is trusting the cracker with the funds themselves. The service's extractors never emit such lines.

These modules are kept here because the formats are real and the kernels are correct — for **local cracking of your own files**, where no third party ever sees the hash.

## Contents

| Module | Wallet | Why it is here |
| --- | --- | --- |
| `90020` `$wasabi$` | [Wasabi](wasabi/) | The BIP38 line carries the full 32-byte encrypted private key; after a crack the key is fully exposed. (Its witness is also the weakest of the family, 2⁻³², inherent to BIP38.) |

## Using a module

1. Build hashcat **v8.0.0 or newer** from source, then drop the module in:

   ```
   cp wasabi/module_90020.c  hashcat/src/modules/
   cp wasabi/m90020-pure.cl  hashcat/OpenCL/
   cd hashcat && make modules
   ```

2. Produce the hash line with the wallet's extractor (see the module's folder — a ready Python extractor with its own README is included).
3. Crack locally:

   ```
   ./hashcat -m 90020 wasabi-hash.txt your-dictionary.txt
   ```

## Warning

If someone offers to crack one of these hashes for you, remember: **after a successful crack they hold your entire secret**. Only use these modules on your own machine, with your own files.
