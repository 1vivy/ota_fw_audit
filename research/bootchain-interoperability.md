# Boot-Chain Interoperability Notes

## Current Working Hypothesis

For recent Qualcomm/OPlus devices, the minimal retained cohort may be smaller
than the full boot chain.

The strongest community candidate cohort is:

- `xbl`
- `xbl_config`
- `xbl_ramdump`
- `abl`

This is not yet proven as a universal rule.

## Community Evidence

OPlus/XDA community reports repeatedly describe successful updates where users
retain:

- `xbl`
- `xbl_config`
- `xbl_ramdump`
- `abl`

while updating the rest of firmware.

Relevant threads:

- `https://xdaforums.com/t/guide-using-aosp-like-rom-without-edl-loaders-get-baned.4783062/`
- `https://xdaforums.com/t/how-to-update-your-frimware-and-lineageos-without-edl-tool-being-fixed-or-you-ending-up-with-arb1.4777194/`
- `https://xdaforums.com/t/we-currently-need-to-understand-which-partitions-are-used-for-anti-rollback.4776403/`
- `https://xdaforums.com/t/warning-do-not-flash-crdroid-2026-01-27-or-newer-if-you-want-to-avoid-permanent-arb-anti-rollback-at-least-for-the-time-being.4777038/`

These are useful empirical hints, not proof.

## Structural Clues

`xbltools` documents this older Qualcomm boot relationship:

- `sbl1` loads `tz`, `hyp`, `abl`, and other images from storage
- `xbl_core` is the EDK2-based UEFI loader
- `xbl_core` launches `LinuxLoader.efi`

Source:

- `https://github.com/linux-msm/xbltools`

This suggests `xbl` and `abl` are tightly related, but does not by itself prove
that `tz` or `hyp` must always be retained together with them.

## ABL / LinuxLoader Findings

`gbl_root_canoe` confirms that the exploitable `efisp` path lives in
`LinuxLoader.efi` inside ABL.

Source:

- `https://github.com/superturtlee/gbl_root_canoe`

Current local results:

- OP15 `0300 -> 1010`: GBL path still present
- Xiaomi `pudding` `OS3.0.44.0 -> OS3.0.305.0`: GBL path removed

This supports treating `abl` as one of the key exploit-retention partitions.

## xbl_config Findings

`XBLConfigReader` exposes concrete payloads inside modern `xbl_config` images:

- `pre-ddr.dtbs.bin`
- `post-ddr.dtbs.bin`
- `*_dcb.bin`

Source:

- `https://github.com/Project-Aloha/XBLConfigReader`

Current local results on SM8850 images show four extracted payloads and distinct
hashes across devices/builds. This supports the idea that `xbl_config` carries
more than a simple ARB value and likely contributes to interoperability.

## Risk Model Change

The current OP15 static analysis changed the risk model in an important way:

- not all "subsystem firmware" should be treated as independent of the boot chain
- several blobs are directly referenced by `xbl`, `tz`, `hyp`, or `devcfg`

Strong OP15 examples:

- `xbl` references `boot_prepare_cpucp`, `boot_reset_cpucp`, `boot_shrm_mini_dump_init`,
  `SOCCP_BIN_PARTITION`, `DCP_BIN_PARTITION`, `PDP_CDB`, and QUP firmware loading
- `hyp` references `soccp_bring_up`, `dcp_bring_up`, and multiple `PILSubsys_*` paths
- `tz` references `enable_modem`, `enable_bluetooth`, CPUCP memory regions, and TME feature paths
- `devcfg` references `/cpucp/cpucpcfg`, `enable_modem`, `enable_bluetooth`, and `spu_service`

This means blobs like `cpucp`, `shrm`, `soccp`, `dcp`, `qupfw`, `pdp`, and friends are better modeled as:

- early-chain-coupled firmware
- lower EDL risk than `xbl/tz/hyp`, but still capable of causing late-boot failure if mixed

So the risk model now needs at least three buckets:

- hard boot-chain cohort
- bootloader-coupled / late-boot-risk firmware
- mostly runtime subsystem firmware

## Tool Limitations Observed

`xbltools/unpackxbl` currently fails on the tested SM8850 vendor `xbl.img`
samples with:

- `Failed to find XBL_Core program header`

This likely means the heuristic used for older layouts does not directly match
current vendor packaging. The failure itself is useful: we should not assume the
modern `xbl` internal layout matches older public tooling.

## Why Certs and Metadata Matter

The most important fields for static compatibility remain:

- root cert hash
- `SW_ID`
- `HW_ID`
- `OEM_ID`
- `anti_rollback_version`
- binding flags

If these change, the chance of safe mixing drops sharply.

If these stay the same, that only establishes that two images remain in the same
trust domain. It does not prove boot compatibility, but it helps explain why a
smaller retained cohort might work.

## Open Questions

- Is `xbl_ramdump` actually required for compatibility, or just flashed with
  `xbl` out of habit?
- Are `tz` and `hyp` forward-compatible often enough to live outside the
  retained minimal cohort?
- Does `uefi` behave more like `xbl`/`abl`, or more like a forward-compatible
  helper blob on these platforms?
- Which fields, if any, in `xbl_config` correspond directly to cohort-level
  coupling beyond ARB and DDR/DCB payload data?

## Current Conservative Policy

Until proven otherwise:

- treat the whole boot chain as a hard cohort
- treat the `abl/xbl/xbl_config/xbl_ramdump` retained subset as an empirical
  candidate, not a guaranteed-safe rule
- treat `cpucp`, `shrm`, `pdp`, `soccp`, `dcp`, `qupfw`, and related config blobs
  as bootloader-coupled firmware rather than ordinary optional subsystem blobs
- only relax cohort boundaries when both static metadata and real-world reports
  agree
