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
