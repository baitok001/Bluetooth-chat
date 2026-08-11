# Bluetooth Chat App

Starter Flutter app for iOS and Android with:

- Bluetooth-style device discovery UI
- text and emoji chat
- avatar selection from gallery

## Run locally

1. Install Flutter SDK
2. Run:

```bash
flutter pub get
flutter run
```

## Notes

The current version is a polished starter UI. Messages are protected by a mutual-authentication handshake (Ed25519 device identity + ephemeral X25519 ECDH, ChaCha20-Poly1305 AEAD with replay-safe counters) instead of a shared passphrase — see `docs/superpowers/specs/2026-08-11-secure-pairing-protocol-design.md` for the protocol design. Note: this app currently only implements the BLE *central/client* role (`connectToDevice`), so two phones running this app cannot yet connect to each other directly — a BLE peripheral/GATT-server role is a separate, not-yet-implemented piece of work.
