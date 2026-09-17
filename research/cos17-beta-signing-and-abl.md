# ColorOS 17 Beta (ossi) — Signing and ABL Review

Notes from adding `c17_qcom.zip` to the corpus and comparing it against the
prior Android 17 beta and the ColorOS 16 builds already tracked here.

## Scope and the confound to keep in mind

Three build generations are compared:

| Label | Manifest | Codename | Device code | OS |
|---|---|---|---|---|
| ColorOS 16 | `CPH2747_11.A.30_0300` | infiniti | OP611FL1 | A16 / 16.0.5.700 |
| ColorOS 16 (later) | `CPH2745_16.0.5.703` | infiniti | OP611FL1 | A16 / 16.0.5.703 |
| A17 beta | `CPH2747_11.C.01_1010` | infiniti | OP611FL1 | A17 / 17.0.0.12 |
| ColorOS 17 beta | `PLK110_11.C.61_1610` | **ossi** | **OP60FFL1** | A17 / 17.0.0.100 |

**The COS17 beta is a different device.** `ossi` / OP60FFL1 / PLK110 is not
`infiniti` / OP611FL1 / CPH2745+CPH2747, even though both are SM8850 on the
`canoe` platform and both are marketed as OnePlus 15 (this one as the CN
一加 15). Only 4 of 50 firmware images are byte-shared between them.

So the COS16 → A17-beta step isolates an OS change on fixed hardware, while
the A17-beta → COS17-beta step mixes an OS change with a device change. Every
claim below states which of the two it rests on.

The COS17 beta package is also not a retail package. The vendor partition is
still fingerprinted `oplus/ossi/ossi:16/BP2A.250605.015/1789230386515` —
Android 16, codename-as-product, raw-timestamp incremental — while the
`my_manifest` product overlay is
`OnePlus/PLK110/OP60FFL1:17/CP2A.260605.016`. It arrived as a flat zip of
`<partition>.img` members with no `payload.bin` and no OTA metadata, which is
how firmware is handed around during bring-up, not how it ships.

## Finding 1 — the ABL `efisp` path is gone

This is the significant change.

| Build | `gbl_vulnerable` | `efisp` hits | LinuxLoader.efi |
|---|---|---|---|
| COS16 16.0.5.700 | true | 1 | 778240 B |
| COS16 16.0.5.703 | true | 1 | 778240 B |
| A17 beta 17.0.0.12 | true | 1 | 778240 B |
| **COS17 beta 17.0.0.100** | **false** | **0** | **782336 B** |

`abl` itself is 278528 bytes in all four. The `efisp` string is absent both
from the raw ABL scan and from the LZMA-decompressed UEFI payload, and
`extractfv` extracted a valid PE (`mz_header: true`, 782336 bytes) from the
COS17 image — so the absence is proven content, not a failed extraction. That
distinction matters: a broken extractor would report the same zero.

The loader grew by exactly 4096 bytes while the path disappeared, so this is a
rebuild rather than a stripped binary.

**The A17 beta is the useful control.** It also rebuilt `abl` relative to
COS16, and it also runs Android 17 — and it kept `efisp`. So Android 17 by
itself does not remove the path. The removal arrived with this build.

What cannot be concluded from one package: whether the removal is a
device-specific ABL for `ossi`, or a platform-wide change that will land on
`infiniti` in its own COS17 build. Settling that needs an `infiniti` COS17
package. `[INFERENCE]` The 4 KB growth alongside the removal reads more like
an intentional loader change than a build-config accident, but that is a
judgement, not a measurement.

## Finding 2 — QTI + OEM dual signing appears

Ten images in the COS17 beta carry two independent signatures over one shared
hash table. Layout of `xbl.img` (MBN hash-table header v7):

```text
+0x0004     36 B  hash-table header
+0x0028     24 B  common metadata      <- shared, one per image
+0x0040    224 B  QTI  metadata
+0x0120    224 B  OEM  metadata
+0x0200    432 B  hash table           <- what both signatures cover
+0x03b0    104 B  QTI  signature       ECDSA P-384
+0x0418   3360 B  QTI  cert chain
+0x1138    104 B  OEM  signature       ECDSA P-384
+0x11a0   3360 B  OEM  cert chain
```

Two chains to two unrelated roots:

- QTI: `CASS - SBL4` <- `SRoT MBNv7 Image Signing Root CA 6 SubCA 1` <-
  `SRoT MBNv7 Image Signing Root CA 6`, root hash
  `0x6d8d595fc1ad2f80383f266453f9b48b35f48a097cc81b1ec282161c561d47f6`
- OEM: `OPLUS SM8850 Attestation` <- `OPLUS Attestation CA` <-
  `OPLUS ROOT CA 1`, root hash
  `0x51a5acc6bfee42dfe62a8ef1ee0c5e04912037005a7c9658dcc91e500ffcdb0e`

### The binding flags explain the purpose

The two 224-byte metadata blocks differ in exactly four fields:

| Field | QTI | OEM |
|---|---|---|
| `oem_id` | `0x0` | `0x51` (OPlus) |
| `bound_to_product_segment_id` | true | false |
| `bound_to_oem_id` | false | true |
| `bound_to_oem_product_id` | false | true |

Both bind to `soc_hw_version`. Neither binds to JTAG ID, serial numbers, or
lifecycle state, and `transfer_root` is false on both.

The split is the answer to "what is it for": the two signatures assert
different things.

- Qualcomm binds the image to the **silicon** — SoC hardware version and
  product segment — and deliberately not to any OEM. On `cpucp` and
  `featenabler` the QTI side covers two SoC versions (`0xa022,0xa01b`) where
  the OEM side covers only `0xa01b`, i.e. one Qualcomm-signed binary valid
  across steppings.
- OPlus binds the same bytes to **its own devices** — SoC hardware version
  plus OEM ID `0x51` plus OEM product ID.

The QTI root hash lives in ROM/PBL and is not OEM-fusable; the OEM root hash
lives in OEM fuses. An image carrying both can only be accepted if both roots
accept it: Qualcomm attests authorship of its own boot and TrustZone code, the
OEM attests device scope.

### Which images, and why the set makes sense

| Signed by | Images | `software_id` |
|---|---|---|
| QTI + OEM | `xbl`, `tz`, `hyp`, `cpucp`, `featenabler`, `tz_qti_config`, `xbl_ac_config`, `tz_ac_config`, `hyp_ac_config` | `0x36`, `0x7`, `0x15`, `0x31`, `0xc`, `0xa1`, `0x95`/`0x96`/`0x97` |
| QTI only | `multiimgqti` (no OEM metadata block at all) | `0x23` |
| OEM only | `xbl_config`, `uefi`, `devcfg`, `keymaster`, `uefisecapp`, `oplus_sec`, `secretkeeper`, `cpucp_dtb`, `multiimgoem`, `spuservice`, `xbl_ramdump` | `0x25`, `0x9`, `0x5`, `0xc`, ... |

The dual-signed set is exactly the Qualcomm-authored components plus their
XPU/SMMU access-control configs, which take consecutive IDs
`0x95`/`0x96`/`0x97`. Everything OEM-authored or device-configurable — the DCB
in `xbl_config`, `devcfg`, the trustlets, `oplus_sec` — is OEM-only.

### It is not a ColorOS 17 or QSSI 17 standard

The v7 header has always carried the `qti_*` size fields, so nothing about the
format is new. Across the corpus, dual signing does not track OS version or
SoC:

| Build | Codename | SoC | Android | Dual-signed |
|---|---|---|---|---|
| CPH2747 11.C.01_1010 | infiniti | sm8850 | **17** | **0 / 21** |
| CPH2745 16.0.5.703 | infiniti | sm8850 | 16 | 0 / 21 |
| CPH2747 11.A.30_0300 | infiniti | sm8850 | 16 | 0 / 21 |
| pudding OS3.0.305.0 | pudding | **sm8850** | — | 0 / 20 |
| pudding OS3.0.44.0 | pudding | sm8850 | — | 0 / 20 |
| CPH2653 (x3) | dodge | sm8750 | 15–16 | 0 / 13 |
| FroggerPro B4.1 | froggerpro | sm7750 | — | 0 / 12 |
| **PLK110 11.C.61_1610** | **ossi** | sm8850 | 17 | **10 / 21** |

An Android 17 build on the same SoC from the same vendor has zero. A different
vendor's SM8850 has zero. SM8850 therefore does **not** require a QTI
signature on `xbl`/`tz`/`hyp` — retail firmware boots with OEM-only
signatures on those images, so the QTI signature here is additive.

`[INFERENCE]` The most consistent reading is that these are Qualcomm
BSP-delivered binaries carried through with their QTI signature retained and
then OEM co-signed, where production packaging ships the OEM signature alone.
That fits the other pre-production markers in this package. The alternative —
that OPlus is moving to retained dual signing for COS17 — cannot be ruled out
from a single engineering build, and would be visible in the first retail
COS17 firmware.

## Finding 3 — AVB rollback index jumps a quarter

`vbmeta_system` and `vbmeta_vendor` carry timestamp-shaped rollback indices:

| Build | Rollback index | As date |
|---|---|---|
| COS16 16.0.5.700 | 1772323200 | 2026-03-01 |
| COS16 16.0.5.703 | 1775001600 | 2026-04-01 |
| A17 beta 17.0.0.12 | 1772323200 | 2026-03-01 |
| COS17 beta 17.0.0.100 | 1788220800 | 2026-09-01 |

Two observations. The A17 beta sits at 2026-03-01, *behind* the 16.0.5.703
retail build at 2026-04-01 — consistent with the A17 beta having branched from
the 16.0.5.700 base rather than from the later retail build. And the COS17
beta advances five months to 2026-09-01, matching its
`ro.vendor.build.security_patch=2026-09-01`.

AVB public keys are unchanged throughout. `vbmeta` itself stays at rollback
index 0 in every build.

## Finding 4 — nothing else security-relevant moved

- **UEFI Setup Mode: unchanged.** All four builds report `setup_mode` — no
  PK/KEK enrollment data in `uefi.img`, `xbl.img`, or `uefisecapp.img`, so
  `gBS->LoadImage` still accepts unsigned EFI images. Secure Boot is not what
  closed the `efisp` path; the path was simply removed from ABL.
- **Anti-rollback: still 0.** Every OEM metadata block in every tracked build
  reports `anti_rollback_version: 0`. No ARB burn in this generation.
- **OEM root of trust: unchanged.** `OPLUS ROOT CA 1` across all OPlus builds,
  including the COS17 beta. No key rotation.
- **Signature algorithm: unchanged.** ECDSA / secp384r1 / SHA384 throughout,
  both parties.

## What each step actually changed

**COS16 16.0.5.700 → A17 beta 17.0.0.12** (same device, isolates the OS):
47 of 50 partitions changed, including 18 boot-chain images and ABL itself.
Only `oplus_sec`, `splash`, and `tme_seq_patch` were untouched. Yet *zero*
security-relevant flags fired — GBL intact, Setup Mode unchanged, ARB 0, no
dual signing, no key or binding change. A large rebuild with no change to the
trust posture.

**A17 beta 17.0.0.12 → COS17 beta 17.0.0.100** (device + OS): 46 of 50
changed, the same 18 boot-chain images, with `multiimgqti`, `oplus_sec`,
`spuservice`, and `tme_seq_patch` byte-identical. Flags:
`gbl_exploit_lost`, `signing_parties_changed`, `avb_rollback_changed`,
`boot_chain_changed`.

EDL-risk images (`xbl`, `xbl_config`, `tz`, `hyp`) changed in both steps, so
neither package is safe to mix with the other's boot chain.

## Pre-existing condition — `spuservice` ships Qualcomm test keys

Not a COS17 change, but worth recording. `spuservice.img` is byte-identical
between the COS17 beta and the A17 beta, and in both it is signed by
Qualcomm's *"General Use Test Key (for testing only)"* SecTools chain:

```text
CN=SecTools Test User, O=SecTools, L=San Diego
  <- OU=General Use Test Key 0 (for testing only), OU=CDMA Technologies, O=QUALCOMM
    <- OU=General Use Test Key (for testing only), OU=CDMA Technologies, O=QUALCOMM
```

Root hash `0x9cda6268c11916ff53b41f2b1701e2758fc3bbd227538ee127158f7c9527a454`.
Its OEM metadata is unbound: `oem_id 0x0`, `soc_hw_version 0x0`, every
`bound_to_*` false.

Whether a device would accept it depends on the fused OEM root hash — on a
production part with the OPlus root fused, a test-key-signed image should fail
verification. Recorded as an anomaly in the vendor's own firmware, not as an
exploitable finding.

## Data-quality corrections

These findings required fixing the tooling first, and two of the fixes change
how earlier manifests should be read.

1. **`elf_parser` had the v7 header word order wrong.** Words 6 and 7 were
   labelled `oem_signature_size`/`qti_cert_chain_size`; the real order is
   `qti_cert_chain_size`/`oem_signature_size`. Region offsets summed correctly
   by coincidence whenever the QTI sizes were zero — which was every build in
   the corpus until this one. With ten non-zero QTI regions, the Qualcomm cert
   chain was being located in the wrong place and silently never extracted.
   This is why "did the Qualcomm root certificate hash change?" had never been
   answerable here.

2. **`androidtool` recorded `common_metadata.software_id` as a constant.**
   Every pre-existing manifest reports `0x25` for every partition — 13/13,
   21/21, 20/20, across four devices and three vendors. `0x25` is
   `xbl_config`'s real value, smeared across all images. The in-tree decoder
   returns 16 distinct values, internally consistent in ways a bug would not
   be: all six TrustZone trustlets share `0xc`, the three access-control
   configs take consecutive `0x95`/`0x96`/`0x97`, and `tz`/`hyp`/`uefi`/
   `devcfg` land on the canonical `0x7`/`0x15`/`0x9`/`0x5`.

3. **`androidtool` reported a root certificate absent from the image.** For
   `spuservice` and `multiimgqti` it recorded `OPLUS ROOT CA 1`. A census of
   every parseable X.509 in those two files shows that certificate is not
   present: `spuservice` carries only the Qualcomm test-key chain,
   `multiimgqti` only the Qualcomm SRoT chain.

Consequence for the reports: the 21 `common_metadata` rows in
`diff_infiniti_1010_vs_ossi_1610.json` (17 `software_id`, 4
`secondary_software_id`) are tooling corrections, not firmware changes. No
summary flag derives from that section, so the headline verdicts are
unaffected. The `common_metadata` block in the five older manifests should be
treated as untrusted; repairing it needs the original OTA packages, which are
no longer on disk.

## Open questions

- Does `infiniti` lose `efisp` in its own COS17 build, or is the removal
  specific to `ossi`? One `infiniti` COS17 package settles it.
- Does retail COS17 firmware retain the QTI signatures, or is dual signing an
  artifact of this engineering package?
- What is SoC hardware version `0xa022`, which only the QTI metadata on
  `cpucp` and `featenabler` accepts alongside `0xa01b`?
- Is the 4 KB LinuxLoader growth accompanied by a replacement mechanism for
  whatever `efisp` served, or is the capability simply gone?
