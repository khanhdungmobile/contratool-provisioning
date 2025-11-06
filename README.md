# CONTRATOOL provisioning

Scripts and assets to generate Android Device Owner provisioning payloads for CONTRATOOL.

## Files
- uto-repack.ps1: rebuilds and signs the APK, applying overrides.
- samsung_tool.py: generates JSON + QR provisioning payloads.
- overrides/: resource/smali overrides applied during rebuild.
- provisioning.json: sample payload (update the download URL/checksum when publishing new APK).
- provisioning_qr.png: QR code generated from the payload.
