# fw_audit

`fw_audit` is a local OTA firmware inventory and comparison toolkit for Qualcomm Android devices.

It is built for questions like:

- Which non-HLOS images changed between two OTAs?
- Did `xbl_config` ARB increment?
- Did the Qualcomm root certificate hash change?
- Did signing or hardware-binding metadata change?
- Is ABL still GBL-vulnerable?
- Would UEFI Secure Boot block unsigned EFI loading even if ABL still has the GBL path?

## Layout

```text
fw_audit/
  profiles/
  tools/
    analyze_ota.py
    compare_otas.py
    lib/
  manifests/
  reports/
```

## Profiles

Profiles are codename-centric.

- Prefer `vendor_codename_soc.yaml` naming.
- Use the device `codename` as the canonical identifier.
- Put marketing names and model numbers in metadata, not short aliases.

Current reference profiles:

- `profiles/boilerplate.yaml`
- `profiles/generic_sm8850.yaml`
- `profiles/oneplus_dodge_sm8750.yaml`
- `profiles/oneplus_infiniti_sm8850.yaml`
- `profiles/xiaomi_pudding_sm8850.yaml`

Profile schema:

```yaml
profile_id: vendor_codename_soc
manufacturer: VendorName
device_name: Marketing Device Name
codename: codename
aliases: []
soc: soc_name
model_numbers: []
source_references: []
notes: []
partitions:
  boot_chain: []
  subsystem_firmware: []
  low_priority: []
  boundary: []
```

## Analyze

Analyze directly from a full OTA zip:

```bash
python3 fw_audit/tools/analyze_ota.py \
  --profile fw_audit/profiles/xiaomi_pudding_sm8850.yaml \
  --ota pudding-ota_full-OS3.0.44.0.WPCCNXM-user-16.0-a95973ab2c.zip \
  --out fw_audit/manifests/pudding_OS3.0.44.0.json
```

Analyze an incremental/partial OTA by supplying its source full OTA:

```bash
python3 fw_audit/tools/analyze_ota.py \
  --profile fw_audit/profiles/oneplus_infiniti_sm8850.yaml \
  --ota CPH2747_11_C_OTA_0300-1010_patch_o2ZAY3_10100111.zip \
  --base-ota CPH2747_11.A.30_0300_202602270114.zip \
  --out fw_audit/manifests/CPH2747_11.C.01_1010.json
```

By default, extraction uses a temporary directory and cleans it up after analysis.
You can override the extraction location with `--work-dir`.

- Full OTA: extract directly into `--work-dir`
- Incremental OTA: extract into `--work-dir/base` and `--work-dir/target`

Tracked `.img` files in those directories are deleted before extraction to avoid stale results.
The working directory is internal scratch/output state and is not embedded in manifests.

## Compare

```bash
python3 fw_audit/tools/compare_otas.py \
  --risk-dict fw_audit/risk_dictionary.yaml \
  fw_audit/manifests/old.json \
  fw_audit/manifests/new.json \
  --out fw_audit/reports/diff.json
```

## Manifest Highlights

Top-level manifest fields include:

- `profile_id`
- `manufacturer`
- `device_name`
- `device_codename`
- `soc`
- `ota_metadata`
- `source_ota`
- `base_ota`
- `ota_kind`
- `uefi_setup_mode`
- `partitions`

Per-partition fields include:

- `sha256`
- `format`
- `qc_image_version`
- `oem_image_version`
- `qualcomm_metadata`
- `avb`
- `gbl` for `abl`

## Security-Specific Checks

### Qualcomm metadata

For supported ELF firmware images, `androidtool` output is parsed into `qualcomm_metadata`.

This captures:

- ARB values
- root certificate hashes
- SoC and OEM binding
- signing algorithm and curve
- cert chain structure

### GBL exploit state

`abl` images are checked for the `efisp` EFI-loading path.

- `gbl_vulnerable: true` means ABL still contains the path
- `gbl_vulnerable: false` means it was not found

The detector scans raw ABL data and embedded LZMA-compressed UEFI payloads.

### UEFI Setup Mode

`uefi_setup_mode` is a platform-level check derived from `uefi.img`, `xbl.img`, and `uefisecapp.img`.

This matters because a GBL-vulnerable ABL is not enough by itself.
If the platform boots in UEFI User Mode with PK enrolled, unsigned EFI loading can still be blocked.

Relevant fields:

- `overall_verdict`
- `gbl_loadimage_ok`
- `sources_checked`

## Notes

- `payload_dumper` is used for OTA extraction.
- `androidtool` from `Android_Tool_RUST` is used for Qualcomm signing metadata when available.
- The comparison report is JSON-only by design.
- The risk dictionary is intentionally human-maintained and conservative.
