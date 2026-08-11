import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:bluetooth_low_energy/bluetooth_low_energy.dart';
import 'package:flutter/foundation.dart' show debugPrint;
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

  // Outbound writes/notifies serialize through this chain so two overlapping
  // sends (e.g. a double-tapped send, or sendFile racing sendMessage) can
  // never interleave their chunks on the wire.
  Future<void> _txChain = Future<void>.value();

  // Received frames are dispatched to SecureChannelService.receiveFrame
  // through this chain, one at a time in arrival order, so two frames
  // arriving close together can't both read the same AEAD receive counter
  // before either increments it.
  Future<void> _rxChain = Future<void>.value();

  // Pausing/resuming the peripheral+central roles (advertise/host GATT
  // server, scan) serializes through this chain so a fast state flip (e.g.
  // handshaking immediately followed by failed) can't let a resume and a
  // pause run out of order and leave the device in neither state.
  Future<void> _roleChain = Future<void>.value();

  // Guards the crypto-handshake phase only (HELLO/RESPONSE/FINISHED). Armed
  // when a session enters `handshaking`, disarmed as soon as the handshake
  // itself completes (successfully or not) or the session tears down. Does
  // not cover the human trust-prompt wait that can follow a completed
  // handshake — that's bounded by user interaction, not this timer.
  Timer? _handshakeWatchdog;
  static const Duration _handshakeTimeout = Duration(seconds: 30);

  // Tracks whether the last attempt to host a GATT server + advertise
  // succeeded, so a failure (unsupported hardware, denied advertise
  // permission) is observable instead of silently degrading to
  // central-only with no signal anywhere.
  bool _peripheralRoleActive = false;
  bool get isPeripheralRoleActive => _peripheralRoleActive;

  bool _disposed = false;

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

      // The rewrite from flutter_blue_plus dropped adapter-state handling
      // (the old code called FlutterBluePlus.turnOn()). There's no
      // equivalent "request the adapter turn on" call in this plugin, but
      // failing here with a clear message — instead of letting
      // startDiscovery() below throw an opaque plugin error — means the
      // caller gets a catchable, understandable failure instead of a silent
      // stuck "scanning" state.
      final adapterState = _centralManager.state;
      if (adapterState != BluetoothLowEnergyState.poweredOn) {
        throw StateError(
          'Bluetooth is not available (adapter state: $adapterState). '
          'Turn Bluetooth on and try again.',
        );
      }

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

      await _enqueueRoleTransition(_startHostingAndDiscovery);

      _initialized = true;
    } catch (_) {
      _initialized = false;
      rethrow;
    } finally {
      _initializing = null;
    }
  }

  // Runs [action] (a pause or resume of the peripheral/central roles) after
  // any previously-queued role transition has finished, so pause/resume
  // calls triggered by fast state flips or a manual refresh can never run
  // concurrently or complete out of order.
  Future<void> _enqueueRoleTransition(Future<void> Function() action) {
    final future = _roleChain.then((_) => action());
    _roleChain = future.catchError((_) {});
    return future;
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
      _peripheralRoleActive = true;
    } catch (e) {
      // Peripheral/advertising role unavailable on this device (unsupported
      // hardware, denied advertise permission, or an advertisement payload
      // too large — a 128-bit service UUID alone consumes 18 of a BLE
      // advertisement's 31 bytes, so a long display name can push this over
      // the limit on some platforms). Not fatal to the central role, but
      // must not be completely silent: flag it and continue to
      // central-role discovery below regardless.
      _peripheralRoleActive = false;
      debugPrint(
          'BluetoothChatService: peripheral/advertising role unavailable: $e');
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
    _peripheralRoleActive = false;
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

  // Restarts both roles — discovery *and* advertising/hosting — not just
  // discovery, so the user-facing "refresh" action can also recover a
  // peripheral role that silently died earlier (see _startHostingAndDiscovery).
  Future<void> startScanning() async {
    if (!isChannelAvailable(_channelState)) {
      return;
    }
    discoveredDevices.clear();
    await _enqueueRoleTransition(_startHostingAndDiscovery);
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
    _armHandshakeWatchdog();

    // Any BLE call below (connect timeout, peer out of range, GATT error,
    // handshake I/O failure) is a routine condition, not a programming
    // error — but left unhandled it would propagate out of this method
    // with the busy slot still claimed (state stuck at `handshaking`,
    // advertising/discovery both stopped, and no disconnect event able to
    // rescue it once `_connectedPeripheral` has been assigned). Every
    // failure path here must go through _teardownConnection so the slot is
    // always released.
    try {
      await _centralManager.connect(peripheral);
      // Assigned as soon as the physical link exists so that any failure
      // from this point on can be cleaned up (and the peer disconnected)
      // by _teardownConnection.
      _connectedPeripheral = peripheral;

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
        await _teardownConnection(resultingState: SecureChannelState.failed);
        return;
      }

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

      _frameCodec = BluetoothFrameCodec(onFrame: _enqueueReceivedFrame);

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
    } catch (_) {
      await _teardownConnection(resultingState: SecureChannelState.failed);
      rethrow;
    }
  }

  // Enqueues a write onto the shared outbound chain instead of writing
  // immediately, so two overlapping sends (handshake frames racing a data
  // frame, or two overlapping sendMessage/sendFile calls) can't interleave
  // their chunks on the wire. The peripheral/characteristic are captured
  // now (not re-read from the instance fields when the queued write
  // actually runs) so a queued write always targets the peer it was
  // written for, even if a new session has since reassigned those fields.
  Future<void> _sendAsCentral(Uint8List bytes) {
    final peripheral = _connectedPeripheral;
    final characteristic = _remoteCharacteristic;
    if (peripheral == null || characteristic == null) {
      return Future<void>.value();
    }
    final future = _txChain
        .then((_) => _writeCentralChunks(peripheral, characteristic, bytes));
    // Keep the chain alive even if this particular write fails, so a later
    // send isn't permanently blocked by one failed write.
    _txChain = future.catchError((_) {});
    return future;
  }

  Future<void> _writeCentralChunks(
    Peripheral peripheral,
    GATTCharacteristic characteristic,
    Uint8List bytes,
  ) async {
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

    // feed() is synchronous and dispatches to the frame codec's internal
    // buffer immediately. It must run before the `respondWriteRequest`
    // await below — the async gap there means two overlapping write
    // requests aren't serialized by the stream, so if feed() ran after the
    // await, two in-flight writes could feed in whichever order their
    // response futures happened to resolve, reordering the payload.
    _frameCodec?.feed(args.request.value);
    await _peripheralManager.respondWriteRequest(args.request);
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
    _armHandshakeWatchdog();

    _frameCodec = BluetoothFrameCodec(onFrame: _enqueueReceivedFrame);

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

  // See _sendAsCentral for why this enqueues onto the shared _txChain
  // instead of writing immediately, and why the central/characteristic are
  // captured now rather than re-read when the queued write runs.
  Future<void> _sendAsPeripheral(Uint8List bytes) {
    final central = _connectedCentral;
    final characteristic = _localCharacteristic;
    if (central == null || characteristic == null) {
      return Future<void>.value();
    }
    final future =
        _txChain.then((_) => _writePeripheralChunks(central, characteristic, bytes));
    _txChain = future.catchError((_) {});
    return future;
  }

  Future<void> _writePeripheralChunks(
    Central central,
    GATTCharacteristic characteristic,
    Uint8List bytes,
  ) async {
    final maxLength = await _peripheralManager.getMaximumNotifyLength(central);
    var offset = 0;
    while (offset < bytes.length) {
      final end =
          (offset + maxLength < bytes.length) ? offset + maxLength : bytes.length;
      await _peripheralManager.notifyCharacteristic(
        central,
        characteristic,
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
    if (_disposed) {
      return;
    }
    // Reaching this callback means the crypto handshake itself (HELLO/
    // RESPONSE/FINISHED) succeeded, so the handshake watchdog's job is
    // done — the remaining trust-prompt wait, if any, is bounded by user
    // interaction, not by this timer.
    _disarmHandshakeWatchdog();

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
    // dispose() closes the stream controllers; a teardown that was already
    // in flight when dispose() ran (e.g. launched from a disconnect event
    // moments earlier) must not reach `_channelStateController.add()` after
    // that or it throws a StateError on the closed controller.
    if (_disposed) {
      return;
    }
    final wasAvailable = isChannelAvailable(_channelState);
    _channelState = state;
    _channelStateController.add(state);

    final isAvailable = isChannelAvailable(state);
    if (wasAvailable && !isAvailable) {
      unawaited(_enqueueRoleTransition(_pauseHostingAndDiscovery));
    } else if (!wasAvailable && isAvailable) {
      unawaited(_enqueueRoleTransition(_startHostingAndDiscovery));
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
    if (_disposed || inner.isEmpty) {
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
    if (_disposed) {
      return;
    }
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
    _disarmHandshakeWatchdog();
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
    // Set first, before anything else: an already-in-flight
    // unawaited(_teardownConnection()) (e.g. launched a moment earlier by a
    // disconnect event) can still be running concurrently with dispose().
    // _setChannelState checks this flag and no-ops instead of calling
    // `.add()` on a controller dispose() is about to close, which would
    // otherwise throw a StateError.
    _disposed = true;
    _disarmHandshakeWatchdog();

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
    // Also disconnect the remote central if we were acting as the
    // responder (peripheral role) — previously only the central-role link
    // was disconnected here, leaving a connected central talking to a
    // write handler whose subscription had just been cancelled.
    final central = _connectedCentral;
    if (central != null) {
      try {
        await _peripheralManager.disconnect(central);
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
    // Previously left the GATT service published after dispose(), so
    // leaving the chat screen while acting as the responder left the
    // service visible/connectable with nothing left to handle it.
    try {
      await _peripheralManager.removeAllServices();
    } catch (_) {
      // Nothing published, or unsupported — safe to ignore.
    }

    await _incomingTextController.close();
    await _incomingTransferController.close();
    await _channelStateController.close();
    await _trustPromptController.close();
  }

  void _armHandshakeWatchdog() {
    _handshakeWatchdog?.cancel();
    _handshakeWatchdog = Timer(_handshakeTimeout, () {
      // A stuck or hostile peer can otherwise squat the single connection
      // slot indefinitely: nothing else times out a handshake that never
      // completes, and recovery would depend entirely on the remote side
      // choosing to disconnect.
      unawaited(
          _teardownConnection(resultingState: SecureChannelState.failed));
    });
  }

  void _disarmHandshakeWatchdog() {
    _handshakeWatchdog?.cancel();
    _handshakeWatchdog = null;
  }

  // Dispatches a received frame onto the shared inbound chain instead of
  // calling SecureChannelService.receiveFrame directly, so two frames
  // arriving close together are processed one at a time in arrival order
  // rather than both reading the same AEAD receive counter before either
  // increments it. The channel and epoch are captured now (at the moment
  // the frame actually arrived) so a frame queued by one session can never
  // be delivered to a different session's SecureChannelService if a
  // teardown and a new session both happen before this frame's turn comes
  // up in the queue.
  void _enqueueReceivedFrame(FrameType type, Uint8List payload) {
    final channel = _secureChannel;
    if (channel == null) {
      return;
    }
    final epoch = _connectionEpoch;
    final future = _rxChain.then((_) async {
      if (epoch != _connectionEpoch) {
        return;
      }
      await channel.receiveFrame(type, payload);
    });
    _rxChain = future.catchError((_) {});
  }
}
