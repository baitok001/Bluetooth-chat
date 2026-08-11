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

The current version is a polished starter UI. Messages are protected by a mutual-authentication handshake (Ed25519 device identity + ephemeral X25519 ECDH, ChaCha20-Poly1305 AEAD with replay-safe counters) instead of a shared passphrase — see `docs/superpowers/specs/2026-08-11-secure-pairing-protocol-design.md` for the protocol design. Both the BLE central and peripheral (GATT-server) roles are active on both devices at once (via `bluetooth_low_energy`), so two phones running this app can discover and connect to each other directly — whichever side taps "Подключить" first becomes the initiator for that session. See `docs/superpowers/specs/2026-08-11-ble-peripheral-transport-design.md` for the transport design. This hasn't been verified on real hardware from this environment (no physical BLE devices available here) — see that spec's Testing Plan for the manual verification checklist to run on two phones.
