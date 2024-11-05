# SoK: On the Physical Security of UOV-based Signature Schemes

This repository contains auxiliary material for the paper: ["SoK: On the Physical Security of UOV-based Signature Schemes"](https://eprint.iacr.org/2023/335).

Authors:
- [Thomas Aulbach](https://www.uni-regensburg.de/informatics-data-science/qpc/team/thomas-aulbach/index.html)
- [Fabio Campos](https://www.sopmac.de/)
- [Juliane Krämer](https://www.uni-regensburg.de/informatics-data-science/qpc/team/prof-dr-juliane-kraemer/index.html)


## Framework

For testing and benchmarking we copied the framework given in the pqov-paper repository [https://github.com/pqov/pqov-paper](https://github.com/pqov/pqov-paper).
We add our masked versions of the signature schemes UOV and MAYO to the folders ov-Ip and mayo1 in ```m4/crypto_sign```.


## Instructions for testing/benchmarks

Run 
```
make IMPLEMENTATION_PATH=crypto_sign/<scheme>/<version> PLATFORM=nucleo-l4r5zi bin/crypto_sign_<scheme>_<version>_<target_bin>.hex
```
in the directory ```m4``` for generating an executable based on the following possible ```<scheme>/<version>``` combinations:

1. mayo1/m4f
2. mayo1/masked-m4f
3. ov-Ip/m4f
4. ov-Ip/m4f-flash
5. ov-Ip/masked-m4f-flash
6. ov-Ip/ref
7. ov-Ip/ref-flash
8. ov-Ip/masked-ref-flash

For further details, we refer to the [pqm4](https://github.com/mupq/pqm4) project.

# Licenses

Code in this repository that does not indicate otherwise is placed in the public domain.

For the third party code see their licenses:

- [UOV](https://www.uovsig.org/): [https://github.com/pqov/pqov-paper](https://github.com/pqov/pqov-paper)
- [MAYO](https://pqmayo.org/): [https://github.com/PQCMayo/MAYO-M4](https://github.com/PQCMayo/MAYO-M4)
- [ChipWhisperer](https://github.com/newaetech/chipwhisperer): [https://github.com/newaetech/chipwhisperer/blob/develop/LICENSE.txt](https://github.com/newaetech/chipwhisperer/blob/develop/LICENSE.txt)