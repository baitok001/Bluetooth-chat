# BLE Peripheral/GATT-Server Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let two phones running this app connect to each other directly over BLE by giving `BluetoothChatService` a peripheral/GATT-server role alongside its existing central role, both active at once on both devices.

**Architecture:** Replace `flutter_blue_plus` (central-only) with `bluetooth_low_energy` (central + peripheral in one plugin). Define one fixed GATT service/characteristic this app's instances use for discovery and byte transport. `BluetoothChatService` runs `CentralManager` (scan + connect, existing code path, `SecureChannelService(isInitiator: true)`) and `PeripheralManager` (advertise + host GATT server, new code path, `SecureChannelService(isInitiator: false)`) simultaneously; whichever side a connection comes from determines the role for that session. A pure busy-slot rule prevents two sessions from starting at once. None of `SecureChannelService`, `BluetoothFrameCodec`, `TrustStoreService`, or any screen changes — this is a transport-layer swap underneath the existing, already-tested crypto/UI stack.

**Tech Stack:** Flutter/Dart, `bluetooth_low_energy` ^6.2.1 (replaces `flutter_blue_plus`), existing `SecureChannelService`/`BluetoothFrameCodec`/`TrustStoreService`/`IdentityService`.

## Global Constraints

- Public API of `BluetoothChatService` (`discoveredDevices`, `connectedDevice`, `channelStateChanges`, `trustPrompts`, `respondToTrustPrompt`, `sendMessage`, `sendFile`, `connectedPeerIdentityPublicKey`, `initialize`, `startScanning`, `connectToDevice`, `dispose`) keeps the same names/signatures so `ChatScreen` and `SafetyVerificationScreen` require zero changes.
- GATT service UUID: `d48df736-d5d0-4062-ad79-61aec0b78073`. Characteristic UUID: `fdaabf64-712f-41b7-b04c-b7502b38a8f7`, properties `write` + `writeWithoutResponse` + `notify`, permission `write`.
- Android `minSdk` must be pinned to 24; add `BLUETOOTH_ADVERTISE` permission. iOS needs `NSBluetoothAlwaysUsageDescription`.
- No Android SDK/Xcode toolchain is available in this environment, so native builds (`flutter build apk`/`flutter build ios`) cannot be run here — verification is `flutter analyze` plus the existing `flutter test` suite (none of which touches BLE directly). Real two-device behavior needs manual verification on hardware, documented but not run by the plan executor.
- Reference spec: `docs/superpowers/specs/2026-08-11-ble-peripheral-transport-design.md`.

---

## Task 1: Pure busy-slot connection policy

**Files:**
- Create: `lib/services/ble_connection_policy.dart`
- Test: `test/services/ble_connection_policy_test.dart`

**Interfaces:**
- Consumes: `SecureChannelState` (`lib/models/secure_channel_state.dart`, already exists).
- Produces: `bool isChannelAvailable(SecureChannelState state)`, `bool shouldAllowOutgoingConnection(SecureChannelState currentState)`, `bool shouldAcceptIncomingConnection(SecureChannelState currentState)`.

- [ ] **Step 1: Write the failing test**

Create `test/services/ble_connection_policy_test.dart`:

```dart
import 'package:bluetooth_chat_app/models/secure_channel_state.dart';
import 'package:bluetooth_chat_app/services/ble_connection_policy.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('ble_connection_policy', () {
    test('idle and failed are available; every other state is busy', () {
      for (final state in SecureChannelState.values) {
        final expected =
            state == SecureChannelState.idle || state == SecureChannelState.failed;
        expect(isChannelAvailable(state), expected, reason: 'state=$state');
      }
    });

    test('outgoing connections are only allowed while available', () {
      expect(shouldAllowOutgoingConnection(SecureChannelState.idle), isTrue);
      expect(shouldAllowOutgoingConnection(SecureChannelState.failed), isTrue);
      expect(shouldAllowOutgoingConnection(SecureChannelState.handshaking), isFalse);
      expect(shouldAllowOutgoingConnection(SecureChannelState.established), isFalse);
    });

    test('incoming connections are only accepted while available', () {
      expect(shouldAcceptIncomingConnection(SecureChannelState.idle), isTrue);
      expect(shouldAcceptIncomingConnection(SecureChannelState.failed), isTrue);
      expect(
        shouldAcceptIncomingConnection(SecureChannelState.awaitingTrustConfirmation),
        isFalse,
      );
      expect(
        shouldAcceptIncomingConnection(SecureChannelState.identityMismatch),
        isFalse,
      );
    });
  });
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/c/Users/Baitok/flutter/bin/flutter test test/services/ble_connection_policy_test.dart`
Expected: FAIL — `ble_connection_policy.dart` doesn't exist yet.

- [ ] **Step 3: Write `lib/services/ble_connection_policy.dart`**

```dart
import '../models/secure_channel_state.dart';

/// True while no handshake/session is in progress, i.e. it's safe to start
/// or accept a new BLE connection. `failed` counts as available so a device
/// can recover and try again without a manual reset.
bool isChannelAvailable(SecureChannelState state) =>
    state == SecureChannelState.idle || state == SecureChannelState.failed;

/// Whether this device may initiate a new outgoing (central-role) connection
/// attempt right now.
bool shouldAllowOutgoingConnection(SecureChannelState currentState) =>
    isChannelAvailable(currentState);

/// Whether this device should accept a new incoming (peripheral-role)
/// connection attempt right now.
bool shouldAcceptIncomingConnection(SecureChannelState currentState) =>
    isChannelAvailable(currentState);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/c/Users/Baitok/flutter/bin/flutter test test/services/ble_connection_policy_test.dart`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add lib/services/ble_connection_policy.dart test/services/ble_connection_policy_test.dart
git commit -m "feat: add pure busy-slot BLE connection policy"
```

---

## Task 2: Swap the BLE plugin and platform configuration

**Files:**
- Modify: `pubspec.yaml`
- Modify: `android/app/build.gradle.kts`
- Modify: `android/app/src/main/AndroidManifest.xml`
- Modify: `ios/Runner/Info.plist`

**Interfaces:**
- Produces: `bluetooth_low_energy` package available for import in Task 3. No Dart code in this task besides dependency wiring.

- [ ] **Step 1: Remove the old plugin and add the new one**

Run:
```bash
cd "C:\Users\Baitok\Desktop\Azamat\1" && /c/Users/Baitok/flutter/bin/flutter pub remove flutter_blue_plus
```

Run:
```bash
cd "C:\Users\Baitok\Desktop\Azamat\1" && /c/Users/Baitok/flutter/bin/flutter pub add bluetooth_low_energy
```

- [ ] **Step 2: Pin Android minSdk to 24**

In `android/app/build.gradle.kts`, find the line `minSdk = flutter.minSdkVersion` (inside the `defaultConfig` block) and replace it:

```kotlin
        minSdk = 24
```

- [ ] **Step 3: Add the BLUETOOTH_ADVERTISE permission**

In `android/app/src/main/AndroidManifest.xml`, add alongside the existing bluetooth permissions:

```xml
    <uses-permission android:name="android.permission.BLUETOOTH_ADVERTISE" />
```

- [ ] **Step 4: Add the iOS Bluetooth usage description**

In `ios/Runner/Info.plist`, add inside the top-level `<dict>` (this key does not exist yet in the project — central-only `flutter_blue_plus` needed it too, so this was already a pre-existing gap):

```xml
	<key>NSBluetoothAlwaysUsageDescription</key>
	<string>Bluetooth нужен, чтобы находить и подключаться к устройствам поблизости для чата</string>
```

- [ ] **Step 5: Verify dependency resolution**

Run: `cd "C:\Users\Baitok\Desktop\Azamat\1" && /c/Users/Baitok/flutter/bin/flutter pub get`
Expected: completes without errors; `pubspec.yaml`/`pubspec.lock` show `bluetooth_low_energy` and no longer show `flutter_blue_plus`.

- [ ] **Step 6: Commit**

```bash
git add pubspec.yaml pubspec.lock android/app/build.gradle.kts android/app/src/main/AndroidManifest.xml ios/Runner/Info.plist
git commit -m "chore: swap flutter_blue_plus for bluetooth_low_energy (central+peripheral)"
```

Note: `flutter analyze` will now show errors in `lib/services/bluetooth_chat_service.dart` (it still imports `flutter_blue_plus`, which no longer exists as a dependency). That's expected and fixed in Task 3 — don't try to fix it here.

---

## Task 3: Rewrite `BluetoothChatService` around central + peripheral roles

**Files:**
- Modify: `lib/services/bluetooth_chat_service.dart` (full rewrite)

**Interfaces:**
- Consumes: `bluetooth_low_energy` (`CentralManager`, `PeripheralManager`, `UUID`, `GATTService`, `GATTCharacteristic`, `GATTCharacteristicProperty`, `GATTCharacteristicPermission`, `GATTCharacteristicWriteType`, `GATTError`, `Advertisement`, `Peripheral`, `Central`, `ConnectionState`, and the `*EventArgs` types), `ble_connection_policy.dart` (`isChannelAvailable`, `shouldAllowOutgoingConnection`, `shouldAcceptIncomingConnection` from Task 1), plus everything already built in the secure-pairing-protocol work: `IdentityService`, `TrustStoreService`, `SecureChannelService`/`FrameType`/`HandshakeResult`, `BluetoothFrameCodec`, `SecureChannelState`.
- Produces: same public surface as before (see Global Constraints) — `BluetoothDeviceInfo` gains a `peripheral` field (replacing the old `device` field, which held a `flutter_blue_plus` `BluetoothDevice`).

- [ ] **Step 1: Rewrite `lib/services/bluetooth_chat_service.dart`**

```dart
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:bluetooth_low_energy/bluetooth_low_energy.dart';
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart';

import '../models/secure_channel_state.dart';
import 'ble_connection_policy.dart';
import 'bluetooth_frame_codec.dart';
import 'identity_service.dart';
import 'secure_channel_service.dart';
import 'trust_store_service.dart';

final UUID _serviceUUID =
    UUID.fromString('d48df736-d5d0-4062-ad79-61aec0b78073');
final UUID _characteristicUUID =
    UUID.fromString('fdaabf64-712f-41b7-b04c-b7502b38a8f7');

class BluetoothDeviceInfo {
  final String id;
  final String name;
  final bool isConnected;
  final Peripheral? peripheral;

  const BluetoothDeviceInfo({
    required this.id,
    required this.name,
    required this.isConnected,
    this.peripheral,
  });
}

class IncomingTransfer {
  final String fileName;
  final String filePath;

  const IncomingTransfer({required this.fileName, required this.filePath});
}

class IncomingTextMessage {
  final String senderName;
  final String text;

  const IncomingTextMessage({required this.senderName, required this.text});
}

class TrustPromptEvent {
  final String identityPublicKeyBase64;
  final String? bleId;
  final String? displayName;
  final bool isNewDevice;
  final bool isChanged;

  const TrustPromptEvent({
    required this.identityPublicKeyBase64,
    this.bleId,
    this.displayName,
    required this.isNewDevice,
    required this.isChanged,
  });
}

class BluetoothChatService {
  final List<BluetoothDeviceInfo> discoveredDevices = [];
  BluetoothDeviceInfo? connectedDevice;

  final IdentityService _identityService;
  final TrustStoreService _trustStore;
  final CentralManager _centralManager = CentralManager();
  final PeripheralManager _peripheralManager = PeripheralManager();

  BluetoothChatService({
    IdentityService? identityService,
    TrustStoreService? trustStore,
  })  : _identityService = identityService ?? IdentityService(),
        _trustStore = trustStore ?? TrustStoreService();

  final StreamController<IncomingTransfer> _incomingTransferController =
      StreamController.broadcast();
  final StreamController<IncomingTextMessage> _incomingTextController =
      StreamController.broadcast();
  final StreamController<SecureChannelState> _channelStateController =
      StreamController.broadcast();
  final StreamController<TrustPromptEvent> _trustPromptController =
      StreamController.broadcast();

  Stream<IncomingTransfer> get incomingTransfers => _incomingTransferController.stream;
  Stream<IncomingTextMessage> get incomingTextMessages => _incomingTextController.stream;
  Stream<SecureChannelState> get channelStateChanges => _channelStateController.stream;
  Stream<TrustPromptEvent> get trustPrompts => _trustPromptController.stream;

  bool _initialized = false;
  String _localDisplayName = 'Nearby device';
  late final GATTCharacteristic _localCharacteristic;
  Directory? _downloadsDir;

  StreamSubscription<DiscoveredEventArgs>? _discoverySubscription;
  StreamSubscription<GATTCharacteristicNotifiedEventArgs>? _notifiedSubscription;
  StreamSubscription<GATTCharacteristicWriteRequestedEventArgs>?
      _writeRequestedSubscription;
  StreamSubscription<PeripheralConnectionStateChangedEventArgs>?
      _centralManagerConnectionSubscription;
  StreamSubscription<CentralConnectionStateChangedEventArgs>?
      _peripheralManagerConnectionSubscription;

  Peripheral? _connectedPeripheral;
  GATTCharacteristic? _remoteCharacteristic;
  Central? _connectedCentral;

  BluetoothFrameCodec? _frameCodec;
  SecureChannelService? _secureChannel;
  SecureChannelState _channelState = SecureChannelState.idle;
  BluetoothDeviceInfo? _pendingDeviceInfo;
  Completer<bool>? _pendingTrustDecision;
  Uint8List? _connectedPeerIdentityPublicKey;

  Uint8List? get connectedPeerIdentityPublicKey => _connectedPeerIdentityPublicKey;

  void setLocalDisplayName(String name) {
    if (name.trim().isNotEmpty) {
      _localDisplayName = name.trim();
    }
  }

  Future<void> initialize() async {
    if (_initialized) {
      return;
    }
    _initialized = true;

    if (Platform.isAndroid) {
      await Permission.bluetooth.request();
      await Permission.bluetoothScan.request();
      await Permission.bluetoothConnect.request();
      await Permission.bluetoothAdvertise.request();
      await Permission.locationWhenInUse.request();
    }

    _downloadsDir ??= await getApplicationDocumentsDirectory();
    await _trustStore.initialize();

    _localCharacteristic = GATTCharacteristic.mutable(
      uuid: _characteristicUUID,
      properties: const [
        GATTCharacteristicProperty.write,
        GATTCharacteristicProperty.writeWithoutResponse,
        GATTCharacteristicProperty.notify,
      ],
      permissions: const [GATTCharacteristicPermission.write],
      descriptors: const [],
    );

    _writeRequestedSubscription = _peripheralManager.characteristicWriteRequested
        .listen(_handleCharacteristicWriteRequested);
    _peripheralManagerConnectionSubscription = _peripheralManager
        .connectionStateChanged
        .listen(_handlePeripheralManagerConnectionStateChanged);

    _notifiedSubscription =
        _centralManager.characteristicNotified.listen(_handleCharacteristicNotified);
    _centralManagerConnectionSubscription = _centralManager.connectionStateChanged
        .listen(_handleCentralManagerConnectionStateChanged);

    await _startHostingAndDiscovery();
  }

  Future<void> _startHostingAndDiscovery() async {
    await _peripheralManager.removeAllServices();
    await _peripheralManager.addService(
      GATTService(
        uuid: _serviceUUID,
        isPrimary: true,
        includedServices: const [],
        characteristics: [_localCharacteristic],
      ),
    );
    await _peripheralManager.startAdvertising(
      Advertisement(name: _localDisplayName, serviceUUIDs: [_serviceUUID]),
    );

    discoveredDevices.clear();
    await _discoverySubscription?.cancel();
    _discoverySubscription = _centralManager.discovered.listen(_handleDiscovered);
    await _centralManager.startDiscovery(serviceUUIDs: [_serviceUUID]);
  }

  Future<void> _pauseHostingAndDiscovery() async {
    await _discoverySubscription?.cancel();
    _discoverySubscription = null;
    try {
      await _centralManager.stopDiscovery();
    } catch (_) {
      // Already stopped or unsupported in this state — safe to ignore.
    }
    try {
      await _peripheralManager.stopAdvertising();
    } catch (_) {
      // Already stopped — safe to ignore.
    }
  }

  void _handleDiscovered(DiscoveredEventArgs args) {
    final id = args.peripheral.uuid.toString();
    final advertisedName = args.advertisement.name;
    final name =
        (advertisedName != null && advertisedName.isNotEmpty) ? advertisedName : id;
    final info = BluetoothDeviceInfo(
      id: id,
      name: name,
      isConnected: false,
      peripheral: args.peripheral,
    );

    final existingIndex = discoveredDevices.indexWhere((d) => d.id == id);
    if (existingIndex >= 0) {
      discoveredDevices[existingIndex] = info;
    } else {
      discoveredDevices.add(info);
    }
  }

  Future<void> startScanning() async {
    if (!isChannelAvailable(_channelState)) {
      return;
    }
    discoveredDevices.clear();
    try {
      await _centralManager.stopDiscovery();
    } catch (_) {
      // Not currently discovering — safe to ignore.
    }
    await _centralManager.startDiscovery(serviceUUIDs: [_serviceUUID]);
  }

  Future<void> connectToDevice(BluetoothDeviceInfo deviceInfo) async {
    if (!shouldAllowOutgoingConnection(_channelState)) {
      return;
    }
    final peripheral = deviceInfo.peripheral;
    if (peripheral == null) {
      throw Exception('No peripheral handle for this device');
    }

    _pendingDeviceInfo = deviceInfo;
    _setChannelState(SecureChannelState.handshaking);

    await _centralManager.connect(peripheral);
    final services = await _centralManager.discoverGATT(peripheral);

    GATTCharacteristic? characteristic;
    for (final service in services) {
      if (service.uuid != _serviceUUID) {
        continue;
      }
      for (final candidate in service.characteristics) {
        if (candidate.uuid == _characteristicUUID) {
          characteristic = candidate;
        }
      }
    }

    if (characteristic == null) {
      _setChannelState(SecureChannelState.failed);
      await _centralManager.disconnect(peripheral);
      return;
    }

    _connectedPeripheral = peripheral;
    _remoteCharacteristic = characteristic;

    await _centralManager.setCharacteristicNotifyState(
      peripheral,
      characteristic,
      state: true,
    );

    connectedDevice = BluetoothDeviceInfo(
      id: deviceInfo.id,
      name: deviceInfo.name,
      isConnected: true,
      peripheral: peripheral,
    );

    _frameCodec = BluetoothFrameCodec(onFrame: (type, payload) {
      _secureChannel?.receiveFrame(type, payload);
    });

    _secureChannel = SecureChannelService(
      identityService: _identityService,
      isInitiator: true,
      sendFrame: (type, payload) =>
          _sendAsCentral(BluetoothFrameCodec.encode(type, payload)),
      onHandshakeComplete: (result) => _onHandshakeComplete(result),
      onHandshakeFailed: (reason) => _setChannelState(SecureChannelState.failed),
      onData: (data) => _handleDecryptedData(data),
      onChannelError: (reason) => _setChannelState(SecureChannelState.failed),
    );

    await _secureChannel!.start();
  }

  Future<void> _sendAsCentral(Uint8List bytes) async {
    final peripheral = _connectedPeripheral;
    final characteristic = _remoteCharacteristic;
    if (peripheral == null || characteristic == null) {
      return;
    }
    final maxLength = await _centralManager.getMaximumWriteLength(
      peripheral,
      type: GATTCharacteristicWriteType.withoutResponse,
    );
    var offset = 0;
    while (offset < bytes.length) {
      final end =
          (offset + maxLength < bytes.length) ? offset + maxLength : bytes.length;
      await _centralManager.writeCharacteristic(
        peripheral,
        characteristic,
        value: bytes.sublist(offset, end),
        type: GATTCharacteristicWriteType.withoutResponse,
      );
      offset = end;
    }
  }

  void _handleCharacteristicNotified(GATTCharacteristicNotifiedEventArgs args) {
    final peripheral = _connectedPeripheral;
    if (peripheral == null || args.peripheral.uuid != peripheral.uuid) {
      return;
    }
    if (args.characteristic.uuid != _characteristicUUID) {
      return;
    }
    _frameCodec?.feed(args.value);
  }

  void _handleCentralManagerConnectionStateChanged(
    PeripheralConnectionStateChangedEventArgs args,
  ) {
    final peripheral = _connectedPeripheral;
    if (peripheral == null || args.peripheral.uuid != peripheral.uuid) {
      return;
    }
    if (args.state == ConnectionState.disconnected) {
      unawaited(_teardownConnection());
    }
  }

  Future<void> _handleCharacteristicWriteRequested(
    GATTCharacteristicWriteRequestedEventArgs args,
  ) async {
    if (args.characteristic.uuid != _characteristicUUID) {
      return;
    }

    if (_connectedCentral == null) {
      if (!shouldAcceptIncomingConnection(_channelState)) {
        await _peripheralManager.respondWriteRequestWithError(
          args.request,
          error: GATTError.insufficientResources,
        );
        return;
      }
      _startPeripheralSession(args.central);
    }

    final connectedCentral = _connectedCentral;
    if (connectedCentral == null || args.central.uuid != connectedCentral.uuid) {
      await _peripheralManager.respondWriteRequestWithError(
        args.request,
        error: GATTError.insufficientResources,
      );
      return;
    }

    await _peripheralManager.respondWriteRequest(args.request);
    _frameCodec?.feed(args.request.value);
  }

  void _startPeripheralSession(Central central) {
    _connectedCentral = central;
    final deviceInfo = BluetoothDeviceInfo(
      id: central.uuid.toString(),
      name: 'Nearby device',
      isConnected: true,
    );
    _pendingDeviceInfo = deviceInfo;
    connectedDevice = deviceInfo;

    _setChannelState(SecureChannelState.handshaking);

    _frameCodec = BluetoothFrameCodec(onFrame: (type, payload) {
      _secureChannel?.receiveFrame(type, payload);
    });

    _secureChannel = SecureChannelService(
      identityService: _identityService,
      isInitiator: false,
      sendFrame: (type, payload) =>
          _sendAsPeripheral(BluetoothFrameCodec.encode(type, payload)),
      onHandshakeComplete: (result) => _onHandshakeComplete(result),
      onHandshakeFailed: (reason) => _setChannelState(SecureChannelState.failed),
      onData: (data) => _handleDecryptedData(data),
      onChannelError: (reason) => _setChannelState(SecureChannelState.failed),
    );
  }

  Future<void> _sendAsPeripheral(Uint8List bytes) async {
    final central = _connectedCentral;
    if (central == null) {
      return;
    }
    final maxLength = await _peripheralManager.getMaximumNotifyLength(central);
    var offset = 0;
    while (offset < bytes.length) {
      final end =
          (offset + maxLength < bytes.length) ? offset + maxLength : bytes.length;
      await _peripheralManager.notifyCharacteristic(
        central,
        _localCharacteristic,
        value: bytes.sublist(offset, end),
      );
      offset = end;
    }
  }

  void _handlePeripheralManagerConnectionStateChanged(
    CentralConnectionStateChangedEventArgs args,
  ) {
    final central = _connectedCentral;
    if (central == null || args.central.uuid != central.uuid) {
      return;
    }
    if (args.state == ConnectionState.disconnected) {
      unawaited(_teardownConnection());
    }
  }

  Future<void> _onHandshakeComplete(HandshakeResult result) async {
    final identityBase64 = base64.encode(result.peerIdentityPublicKey);
    final decision = await _trustStore.evaluate(
      identityPublicKeyBase64: identityBase64,
      bleId: _pendingDeviceInfo?.id,
      displayName: _pendingDeviceInfo?.name,
    );

    if (decision.isNewDevice || decision.isChanged) {
      _setChannelState(decision.isChanged
          ? SecureChannelState.identityMismatch
          : SecureChannelState.awaitingTrustConfirmation);

      final completer = Completer<bool>();
      _pendingTrustDecision = completer;
      _trustPromptController.add(TrustPromptEvent(
        identityPublicKeyBase64: identityBase64,
        bleId: _pendingDeviceInfo?.id,
        displayName: _pendingDeviceInfo?.name,
        isNewDevice: decision.isNewDevice,
        isChanged: decision.isChanged,
      ));

      final accepted = await completer.future;
      if (!accepted) {
        await _teardownConnection();
        return;
      }

      await _trustStore.trust(
        identityPublicKeyBase64: identityBase64,
        bleId: _pendingDeviceInfo?.id,
        displayName: _pendingDeviceInfo?.name,
      );
    }

    _connectedPeerIdentityPublicKey = result.peerIdentityPublicKey;
    _setChannelState(SecureChannelState.established);
  }

  Future<void> respondToTrustPrompt(bool accept) async {
    _pendingTrustDecision?.complete(accept);
    _pendingTrustDecision = null;
  }

  void _setChannelState(SecureChannelState state) {
    final wasAvailable = isChannelAvailable(_channelState);
    _channelState = state;
    _channelStateController.add(state);

    final isAvailable = isChannelAvailable(state);
    if (wasAvailable && !isAvailable) {
      unawaited(_pauseHostingAndDiscovery());
    } else if (!wasAvailable && isAvailable) {
      unawaited(_startHostingAndDiscovery());
    }
  }

  Future<void> sendMessage(String text) async {
    final channel = _secureChannel;
    if (_channelState != SecureChannelState.established || channel == null) {
      return;
    }
    final content = utf8.encode(text);
    final inner = Uint8List.fromList([0, ...content]);
    await channel.sendData(inner);
  }

  Future<void> sendFile(String filePath, {required String fileName}) async {
    final channel = _secureChannel;
    if (_channelState != SecureChannelState.established || channel == null) {
      throw Exception('Secure channel is not established');
    }

    final file = File(filePath);
    final bytes = await file.readAsBytes();
    final nameBytes = utf8.encode(fileName);
    final nameLength = Uint8List(2);
    ByteData.sublistView(nameLength).setUint16(0, nameBytes.length, Endian.big);
    final inner = Uint8List.fromList([1, ...nameLength, ...nameBytes, ...bytes]);
    await channel.sendData(inner);
  }

  void _handleDecryptedData(Uint8List inner) {
    if (inner.isEmpty) {
      return;
    }
    final innerType = inner[0];
    if (innerType == 0) {
      final text = utf8.decode(inner.sublist(1));
      _incomingTextController
          .add(IncomingTextMessage(senderName: 'Nearby device', text: text));
    } else if (innerType == 1) {
      if (inner.length < 3) {
        return;
      }
      final nameLengthBytes = Uint8List.fromList(inner.sublist(1, 3));
      final nameLength = ByteData.sublistView(nameLengthBytes).getUint16(0, Endian.big);
      const nameStart = 3;
      final nameEnd = nameStart + nameLength;
      if (inner.length < nameEnd) {
        return;
      }
      final fileName = utf8.decode(inner.sublist(nameStart, nameEnd));
      final fileBytes = inner.sublist(nameEnd);
      final safeName = fileName.replaceAll(RegExp(r'[^a-zA-Z0-9._-]'), '_');
      unawaited(_writeIncomingFile(safeName, fileBytes));
    }
  }

  Future<void> _writeIncomingFile(String safeName, List<int> fileBytes) async {
    final filePath = '${_downloadsDir!.path}/$safeName';
    final file = File(filePath);
    await file.writeAsBytes(fileBytes, flush: true);
    _incomingTransferController
        .add(IncomingTransfer(fileName: safeName, filePath: filePath));
  }

  Future<void> _teardownConnection() async {
    final peripheral = _connectedPeripheral;
    if (peripheral != null) {
      try {
        await _centralManager.disconnect(peripheral);
      } catch (_) {
        // Already disconnected — safe to ignore.
      }
    }
    final central = _connectedCentral;
    if (central != null) {
      try {
        await _peripheralManager.disconnect(central);
      } catch (_) {
        // Already disconnected — safe to ignore.
      }
    }

    _connectedPeripheral = null;
    _remoteCharacteristic = null;
    _connectedCentral = null;
    _secureChannel = null;
    _frameCodec = null;
    connectedDevice = null;
    _connectedPeerIdentityPublicKey = null;
    _pendingDeviceInfo = null;

    _setChannelState(SecureChannelState.idle);
  }

  Future<void> dispose() async {
    await _discoverySubscription?.cancel();
    await _notifiedSubscription?.cancel();
    await _writeRequestedSubscription?.cancel();
    await _centralManagerConnectionSubscription?.cancel();
    await _peripheralManagerConnectionSubscription?.cancel();

    final peripheral = _connectedPeripheral;
    if (peripheral != null) {
      try {
        await _centralManager.disconnect(peripheral);
      } catch (_) {
        // Already disconnected — safe to ignore.
      }
    }

    try {
      await _centralManager.stopDiscovery();
    } catch (_) {
      // Not discovering — safe to ignore.
    }
    try {
      await _peripheralManager.stopAdvertising();
    } catch (_) {
      // Not advertising — safe to ignore.
    }

    await _incomingTextController.close();
    await _incomingTransferController.close();
    await _channelStateController.close();
    await _trustPromptController.close();
  }
}
```

- [ ] **Step 2: Wire the local display name from `ChatScreen`**

In `lib/screens/chat_screen.dart`, inside `_bootstrap()`, right before the existing `await _loadNearbyDevices();` call at the end of the method, add:

```dart
    _service.setLocalDisplayName(_myProfile.name);
```

(The name is captured once at startup — if the user changes their display name mid-session, the already-started advertisement keeps the old name until the next app launch. That's an accepted limitation, not a bug: re-advertising live is out of scope for this change.)

- [ ] **Step 3: Analyze**

Run: `cd "C:\Users\Baitok\Desktop\Azamat\1" && /c/Users/Baitok/flutter/bin/flutter analyze`
Expected: no errors. If any `bluetooth_low_energy` API name in Step 1 doesn't match the resolved package version (check `/c/Users/Baitok/flutter/bin/flutter pub deps` and the downloaded package source under `%LOCALAPPDATA%\Pub\Cache` or `~/.pub-cache` if needed), adjust the method/class names to match — the intent (one GATT service+characteristic, central role via `CentralManager`, peripheral role via `PeripheralManager`, chunked writes/notifies, busy-slot gating) must stay the same.

- [ ] **Step 4: Commit**

```bash
git add lib/services/bluetooth_chat_service.dart lib/screens/chat_screen.dart
git commit -m "feat: add BLE peripheral/GATT-server role alongside central role"
```

---

## Task 4: Final integration

**Files:**
- Modify: `README.md`
- No new source files.

- [ ] **Step 1: Run the full analyzer**

Run: `cd "C:\Users\Baitok\Desktop\Azamat\1" && /c/Users/Baitok/flutter/bin/flutter analyze`
Expected: no errors anywhere in the project.

- [ ] **Step 2: Run the full test suite**

Run: `cd "C:\Users\Baitok\Desktop\Azamat\1" && /c/Users/Baitok/flutter/bin/flutter test`
Expected: all tests pass, including the 3 new `ble_connection_policy` tests from Task 1 and every test from the secure-pairing-protocol work (none of that code changed).

- [ ] **Step 3: Update `README.md`**

Replace the caveat sentence added by the previous change:

```markdown
Note: this app currently only implements the BLE *central/client* role (`connectToDevice`), so two phones running this app cannot yet connect to each other directly — a BLE peripheral/GATT-server role is a separate, not-yet-implemented piece of work.
```

with:

```markdown
Both the BLE central and peripheral (GATT-server) roles are active on both devices at once (via `bluetooth_low_energy`), so two phones running this app can discover and connect to each other directly — whichever side taps "Подключить" first becomes the initiator for that session. See `docs/superpowers/specs/2026-08-11-ble-peripheral-transport-design.md` for the transport design. This hasn't been verified on real hardware from this environment (no physical BLE devices available here) — see that spec's Testing Plan for the manual verification checklist to run on two phones.
```

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: describe the dual-role BLE transport"
```
