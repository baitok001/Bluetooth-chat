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
  // The in-flight initialize() run, if any. Lets a second concurrent call to
  // initialize() (e.g. a double-tapped refresh button) await the same run
  // instead of starting the side-effecting setup (permission requests, GATT
  // service/advertising setup, stream subscriptions) a second time in
  // parallel. Cleared once that run finishes, success or failure, so a call
  // made after a genuine failure starts a fresh attempt rather than being
  // stuck replaying a dead future.
  Future<void>? _initializing;
  String _localDisplayName = 'Nearby device';
  // Nullable (not `late final`) so a failed `initialize()` can be retried
  // without hitting a "already initialized" LateInitializationError; built
  // idempotently via `??=` the first time initialize() reaches this point.
  GATTCharacteristic? _localCharacteristic;
  Directory? _downloadsDir;

  // Bumped every time a connection session starts or is torn down. Lets
  // async callbacks that were suspended mid-session (e.g. awaiting a trust
  // prompt decision) detect that the session they belonged to no longer
  // exists by the time they resume, so they can bail out instead of acting
  // on stale/nulled state.
  int _connectionEpoch = 0;

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

  // Deliberately not `async`: the guard checks below must run synchronously
  // (no `await` before them) so that two back-to-back calls to initialize()
  // can never both pass the `_initialized`/`_initializing` checks before
  // either one has registered itself — Dart won't preempt this function
  // between the check and the `_initializing ??= ...` assignment.
  Future<void> initialize() {
    if (_initialized) {
      return Future<void>.value();
    }
    // If a run is already in flight, piggyback on it instead of starting a
    // second concurrent run of the side-effecting setup below. `??=` only
    // evaluates/assigns _doInitialize() when _initializing is currently
    // null, so this is the reentrancy guard.
    return _initializing ??= _doInitialize();
  }

  Future<void> _doInitialize() async {
    // `_initialized` is only flipped to true once every step below has
    // succeeded. If anything throws (e.g. a permission request fails on an
    // odd platform, or the trust store can't open its database), it's reset
    // so the caller can retry by calling initialize() again from scratch
    // instead of being permanently stuck with a half-initialized service.
    // `_initializing` is cleared in `finally` either way, so a retry after a
    // genuine failure starts a fresh run rather than reusing a dead future.
    try {
      if (Platform.isAndroid) {
        await Permission.bluetooth.request();
        await Permission.bluetoothScan.request();
        await Permission.bluetoothConnect.request();
        await Permission.bluetoothAdvertise.request();
        await Permission.locationWhenInUse.request();
      }

      _downloadsDir ??= await getApplicationDocumentsDirectory();
      await _trustStore.initialize();

      _localCharacteristic ??= GATTCharacteristic.mutable(
        uuid: _characteristicUUID,
        properties: const [
          GATTCharacteristicProperty.write,
          GATTCharacteristicProperty.writeWithoutResponse,
          GATTCharacteristicProperty.notify,
        ],
        permissions: const [GATTCharacteristicPermission.write],
        descriptors: const [],
      );

      await _writeRequestedSubscription?.cancel();
      _writeRequestedSubscription = _peripheralManager.characteristicWriteRequested
          .listen(_handleCharacteristicWriteRequested);
      await _peripheralManagerConnectionSubscription?.cancel();
      _peripheralManagerConnectionSubscription = _peripheralManager
          .connectionStateChanged
          .listen(_handlePeripheralManagerConnectionStateChanged);

      await _notifiedSubscription?.cancel();
      _notifiedSubscription =
          _centralManager.characteristicNotified.listen(_handleCharacteristicNotified);
      await _centralManagerConnectionSubscription?.cancel();
      _centralManagerConnectionSubscription = _centralManager.connectionStateChanged
          .listen(_handleCentralManagerConnectionStateChanged);

      await _startHostingAndDiscovery();

      _initialized = true;
    } catch (_) {
      _initialized = false;
      rethrow;
    } finally {
      _initializing = null;
    }
  }

  Future<void> _startHostingAndDiscovery() async {
    // Advertising/hosting a GATT server is the peripheral role. On a device
    // or platform where that's unsupported, or if the advertise permission
    // was denied, this must not take down the central role (scan+connect)
    // with it — so failures here are swallowed and we degrade to
    // scan-and-connect-only rather than losing both roles.
    try {
      await _peripheralManager.removeAllServices();
      await _peripheralManager.addService(
        GATTService(
          uuid: _serviceUUID,
          isPrimary: true,
          includedServices: const [],
          characteristics: [_localCharacteristic!],
        ),
      );
      await _peripheralManager.startAdvertising(
        Advertisement(name: _localDisplayName, serviceUUIDs: [_serviceUUID]),
      );
    } catch (_) {
      // Peripheral/advertising role unavailable on this device — continue
      // to central-role discovery below regardless.
    }

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

    _connectionEpoch++;
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
      onHandshakeFailed: (reason) => unawaited(
          _teardownConnection(resultingState: SecureChannelState.failed)),
      onData: (data) => _handleDecryptedData(data),
      onChannelError: (reason) => unawaited(
          _teardownConnection(resultingState: SecureChannelState.failed)),
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
    _connectionEpoch++;
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
      onHandshakeFailed: (reason) => unawaited(
          _teardownConnection(resultingState: SecureChannelState.failed)),
      onData: (data) => _handleDecryptedData(data),
      onChannelError: (reason) => unawaited(
          _teardownConnection(resultingState: SecureChannelState.failed)),
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
        _localCharacteristic!,
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
    // Captured so that if the session this handshake belongs to is torn
    // down (peer disconnects, teardown runs) while we're suspended on an
    // `await` below, we can tell and bail out instead of resurrecting a
    // dead session or acting on now-nulled state.
    final epoch = _connectionEpoch;

    final identityBase64 = base64.encode(result.peerIdentityPublicKey);
    final decision = await _trustStore.evaluate(
      identityPublicKeyBase64: identityBase64,
      bleId: _pendingDeviceInfo?.id,
      displayName: _pendingDeviceInfo?.name,
    );
    if (epoch != _connectionEpoch) {
      return;
    }

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
      if (epoch != _connectionEpoch) {
        // The session was already torn down (e.g. the peer disconnected)
        // while the trust prompt was outstanding. _teardownConnection()
        // already resolved _pendingTrustDecision and reset state; there's
        // nothing left here to establish or tear down again.
        return;
      }
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

  Future<void> _teardownConnection({
    SecureChannelState resultingState = SecureChannelState.idle,
  }) async {
    // Bump the epoch and resolve any outstanding trust-prompt completer
    // *before* the first await below, so that if _onHandshakeComplete is
    // currently suspended on `await completer.future` for this session, its
    // continuation (which runs as a microtask once we yield) sees the new
    // epoch and bails out instead of trying to establish or re-tear-down a
    // session that no longer exists.
    _connectionEpoch++;
    _pendingTrustDecision?.complete(false);
    _pendingTrustDecision = null;

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

    _setChannelState(resultingState);
  }

  Future<void> dispose() async {
    _pendingTrustDecision?.complete(false);
    _pendingTrustDecision = null;

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
