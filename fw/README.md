# Bundled UEFI firmware

EDK2 firmware images for QEMU, compressed with bzip2. `scripts/check.sh`
boots `examples/uefi` on the system's OVMF (x86_64) and AAVMF (AArch64)
when they are installed (`/usr/share/ovmf`, `/usr/share/AAVMF`), and on
these images otherwise, decompressed into its temporary directory; with
`OSMIUM_FW=bundled` in the environment it uses these images even when the
system has its own.

| File | Platform | Decompressed | Used by check.sh |
|------|----------|--------------|------------------|
| `X64_CODE.fd.bz2`, `X64_VARS.fd.bz2` | OVMF, `qemu-system-x86_64 -machine q35` | 3.5 MiB code, 528 KiB variables | yes, as two pflash drives |
| `ARM64_CODE.fd.bz2`, `ARM64_VARS.fd.bz2` | ArmVirtQemu, `qemu-system-aarch64 -machine virt` | 3 MiB code, 768 KiB variables | yes, each padded to the 64 MiB QEMU's virt flash banks need |
| `RISCV_CODE.fd.bz2`, `RISCV_VARS.fd.bz2` | RiscVVirtQemu, `qemu-system-riscv64 -machine virt` | 8 MiB code, 768 KiB variables | no |

The RISC-V images are not booted by `check.sh`: `examples/uefi` builds for
`x86_64-unknown-uefi` and `aarch64-unknown-uefi` only, as Rust has no
RISC-V UEFI target. They are kept for trying a RISC-V UEFI application by
hand; QEMU's virt flash banks are 32 MiB there:

```sh
bzcat fw/RISCV_CODE.fd.bz2 > code.fd && bzcat fw/RISCV_VARS.fd.bz2 > vars.fd
truncate -s 32M code.fd vars.fd
qemu-system-riscv64 -machine virt -m 256M -nographic \
    -drive if=pflash,unit=0,format=raw,readonly=on,file=code.fd \
    -drive if=pflash,unit=1,format=raw,file=vars.fd
```

## Provenance

The images were added in commit `ae3df28` ("OVMF firmware images for QEMU on
all platforms", 2026-10-23). They were built from a local checkout of
[EDK2](https://github.com/tianocore/edk2) with the `RELEASE` build target and
the `CLANGDWARF` toolchain, from the platform descriptions
`OvmfPkg/OvmfPkgX64.dsc`, `ArmVirtPkg/ArmVirtQemu.dsc` and
`OvmfPkg/RiscVVirt/RiscVVirtQemu.dsc` (the build directories,
`Build/ArmVirtQemu-AArch64/RELEASE_CLANGDWARF` and
`Build/RiscVVirtQemu/RELEASE_CLANGDWARF`, are recorded in the AArch64 and
RISC-V images; the x86_64 image keeps its debug paths inside a compressed
volume). The exact EDK2 revision and build options were not recorded with the
images; the checkout they came from is at tag `edk2-stable202608` (commit
`2970e5699ba6`) as this file is written, which is the likeliest source.

## Licence

EDK2 is distributed under the BSD-2-Clause-Patent licence below (its
`License.txt`). Some EDK2 packages carry third-party code under other
licences (listed in EDK2's `License-History.txt` and in the licence files of
its submodules, such as OpenSSL's in `CryptoPkg`); which of them a firmware
image contains depends on its build options. The images are redistributed
unmodified, apart from the bzip2 compression.

```text
Copyright (c) 2019, TianoCore and contributors.  All rights reserved.

SPDX-License-Identifier: BSD-2-Clause-Patent

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

Subject to the terms and conditions of this license, each copyright holder
and contributor hereby grants to those receiving rights under this license
a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
(except for failure to satisfy the conditions of this license) patent
license to make, have made, use, offer to sell, sell, import, and otherwise
transfer this software, where such license applies only to those patent
claims, already acquired or hereafter acquired, licensable by such copyright
holder or contributor that are necessarily infringed by:

(a) their Contribution(s) (the licensed copyrights of copyright holders and
    non-copyrightable additions of contributors, in source or binary form)
    alone; or

(b) combination of their Contribution(s) with the work of authorship to
    which such Contribution(s) was added by such copyright holder or
    contributor, if, at the time the Contribution is added, such addition
    causes such combination to be necessarily infringed. The patent license
    shall not apply to any other combinations which include the
    Contribution.

Except as expressly stated above, no rights or licenses from any copyright
holder or contributor is granted under this license, whether expressly, by
implication, estoppel or otherwise.

DISCLAIMER

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```
