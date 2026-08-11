# BLE Peripheral/GATT-Server Transport — Design

Date: 2026-08-11
Status: Approved by user, ready for implementation planning

## Problem

`BluetoothChatService` (built during the secure-pairing-protocol work) only implements
the BLE **central/client** role: `connectToDevice` connects outward to a peripheral and
looks for a compatible characteristic. `flutter_blue_plus`, the plugin currently in use,
does not support acting as a peripheral (advertising + hosting a GATT server) at all —
it's central-only. Consequently two phones running this app cannot connect to each other:
whichever one taps "Подключить" has nothing to connect *to*, since neither side ever
advertises a GATT service.

Additionally, the current central-role scan lists every nearby BLE device indiscriminately
(headphones, unrelated peripherals) and blindly probes for "a characteristic with write +
notify", which is unreliable outside of two copies of this exact app happening to expose
one.

## Goals

1. Two phones running this app can discover and connect to each other directly over BLE,
   with no external hardware or third device involved.
2. Both roles run at once on both devices — the app doesn't ask the user to pick
   "host" vs. "join"; whichever side taps "Подключить" first becomes the central/initiator
   for that session, symmetric to how it already works today.
3. Discovery only surfaces other instances of this app, not arbitrary nearby BLE devices.
4. The existing mutual-auth handshake, AEAD channel, trust store, and UI (chat screen,
   trust dialogs, safety verification) are reused unchanged — this is a transport-layer
   swap underneath `BluetoothChatService`, not a protocol change.

Non-goals: background operation (advertising/scanning while the app is backgrounded),
supporting more than one simultaneous peer connection, Windows/Linux/macOS desktop BLE
peripheral support (the app targets Android/iOS).

## Plugin Choice

Replacing `flutter_blue_plus` with `bluetooth_low_energy` (pub.dev, latest 6.2.1),
verified against its actual source: a single plugin exposing both `CentralManager` and
`PeripheralManager`, each independently capable of running at the same time, with GATT
service/characteristic definitions, advertising, and connection-state streams for both
directions on Android and iOS.

Platform requirements this plugin imposes:
- Android `minSdk` 24 (project currently inherits Flutter's default via
  `flutter.minSdkVersion`, which may be lower — needs to be pinned explicitly).
- Android `BLUETOOTH_ADVERTISE` permission (Android 12+), in addition to the
  `BLUETOOTH_SCAN`/`BLUETOOTH_CONNECT` the app already requests.
- iOS `NSBluetoothAlwaysUsageDescription` in `Info.plist` — currently missing from the
  project entirely (a pre-existing gap; central-only `flutter_blue_plus` needed it too).

## GATT Profile

One fixed custom service with one characteristic, used identically regardless of which
side is acting as central vs. peripheral for a given session:

```
Service UUID:        d48df736-d5d0-4062-ad79-61aec0b78073
Characteristic UUID: fdaabf64-712f-41b7-b04c-b7502b38a8f7
Characteristic properties: write, writeWithoutResponse, notify
Characteristic permissions: write
```

- Central scanning is filtered to this service UUID (`CentralManager.startDiscovery
  (serviceUUIDs: [...])`), so the "Поблизости" list only shows other instances of this
  app, not unrelated BLE devices.
- The peripheral's advertisement includes the service UUID and the local user's display
  name (`Advertisement(name: ..., serviceUUIDs: [...])`), so the discovering side's list
  shows a human name instead of just a hardware identifier. This does mean the chosen
  display name is broadcast in the clear to anyone scanning nearby — a minor disclosure
  consistent with the fact that BLE device names are already commonly broadcast; not a
  new class of exposure this app introduces.
- All application bytes (handshake frames and encrypted chat frames, using the existing
  `BluetoothFrameCodec`/`SecureChannelService`, both unchanged) flow through writes to
  this one characteristic (central → peripheral) and notifications on it
  (peripheral → central). Which physical byte-carrying mechanism is used depends only on
  which role a given device is playing in a given session — the framing and crypto layers
  don't know or care.

## Symmetric Dual-Role Operation

On entering the chat screen (mirroring today's auto-scan-on-load), `BluetoothChatService`
now does two things at once instead of one:
- **Peripheral side:** publish the GATT service (`PeripheralManager.addService`) and
  start advertising (`startAdvertising`).
- **Central side:** start scanning for the service UUID (`CentralManager.startDiscovery`),
  populating `discoveredDevices` exactly as before.

Whichever side the user acts on determines the role for that session:
- Tapping "Подключить" on a discovered peer → this device is **central/initiator**:
  `CentralManager.connect`, discover the characteristic, drive a `SecureChannelService`
  with `isInitiator: true` — the exact code path that already existed and is tested.
- A remote device connecting to *our* advertised service and writing to our
  characteristic → this device is **peripheral/responder**: bytes arriving via
  `characteristicWriteRequested` feed a `BluetoothFrameCodec` driving a
  `SecureChannelService` with `isInitiator: false` — code that already exists (built and
  unit-tested during the crypto work) but was previously unreachable for lack of a
  transport that could ever trigger it.

Both paths converge on the same `SecureChannelService` callbacks
(`onHandshakeComplete`/`onData`/etc.), the same `TrustStoreService` evaluation, and the
same `channelStateChanges`/`trustPrompts` streams the UI already listens to — `ChatScreen`
needs no changes for this feature.

## Collision Handling (Priority Rule)

Because both roles are always active, a rare race is possible: two users tap "Подключить"
on each other within the same window, or a peripheral connection arrives while a central
connection attempt is already in flight. Handled with a single-slot busy rule:

- `BluetoothChatService` tracks one `SecureChannelState` for the whole service (as today).
- Whenever that state is anything other than `idle` or `failed` (i.e. a handshake is in
  progress or a session is `established`), the service:
  - stops advertising and stops discovery (so it can't be found or find anyone else while
    busy — prevents new attempts from starting in the first place), and
  - if a peripheral-side connection/write arrives anyway (a central elsewhere already
    mid-attempt before we stopped advertising), it's rejected outright
    (`respondWriteRequestWithError` / disconnecting the central) rather than spawning a
    second `SecureChannelService`.
- On disconnect (either side ends the session, or the handshake fails), the state returns
  to `idle`, and advertising + discovery both resume automatically.

This is a pure precondition check (`shouldAcceptIncomingConnection(currentState)` /
`shouldAllowOutgoingConnection(currentState)` — trivial pure functions), so it gets direct
unit test coverage despite the surrounding BLE plumbing being untestable here.

## Chunking

Default BLE ATT MTU is small (~20 usable bytes) unless negotiated up; several protocol
frames (e.g. the FINISHED handshake message, 82+5 bytes with framing) exceed that. Rather
than negotiating MTU and hoping it's large enough everywhere, outgoing bytes are always
explicitly split before transmission:
- As central: chunk to `CentralManager.getMaximumWriteLength(peripheral, type:
  withoutResponse)` bytes per `writeCharacteristic` call.
- As peripheral: chunk to `PeripheralManager.getMaximumNotifyLength(central)` bytes per
  `notifyCharacteristic` call.

No change needed on the receiving side: `BluetoothFrameCodec.feed()` already buffers
incoming bytes and reassembles frames regardless of how they were chunked in transit —
this was true before this change and remains true now.

## Files Affected

Changed:
- `pubspec.yaml` — remove `flutter_blue_plus`, add `bluetooth_low_energy`
- `lib/services/bluetooth_chat_service.dart` — transport layer rewritten around
  `CentralManager`/`PeripheralManager` instead of `flutter_blue_plus`; public API
  (`discoveredDevices`, `connectedDevice`, `channelStateChanges`, `trustPrompts`,
  `respondToTrustPrompt`, `sendMessage`, `sendFile`, `connectedPeerIdentityPublicKey`,
  `initialize`/`startScanning`/`connectToDevice`/`dispose`) stays the same shape so
  `ChatScreen` and `SafetyVerificationScreen` need no changes
- `android/app/build.gradle.kts` — pin `minSdk = 24`
- `android/app/src/main/AndroidManifest.xml` — add `BLUETOOTH_ADVERTISE`
- `ios/Runner/Info.plist` — add `NSBluetoothAlwaysUsageDescription`

New:
- `lib/services/ble_connection_policy.dart` — the pure busy-slot decision functions
  (`shouldAllowOutgoingConnection`/`shouldAcceptIncomingConnection`) plus their unit test

No changes to `lib/services/secure_channel_service.dart`, `bluetooth_frame_codec.dart`,
`trust_store_service.dart`, `identity_service.dart`, `chat_storage_service.dart`,
`security_service.dart`, or any screen — this is deliberately scoped to the transport
layer only.

## Testing Plan

- **Automated**: unit tests for the busy-slot decision functions in
  `ble_connection_policy.dart` (idle/failed → allow, handshaking/established → deny),
  same style as the existing `evaluateTrustDecision` tests. `flutter analyze` clean,
  full existing test suite (from the secure-pairing-protocol work) still green — none of
  that code changes.
- **Manual, on real hardware (not run by me)**: two physical devices running the app,
  verifying discovery shows the peer's name, connecting from either side reaches the
  existing TOFU trust dialog and then `established`, chat messages/files flow both
  directions, and the collision rule holds up when both sides tap connect at once.
