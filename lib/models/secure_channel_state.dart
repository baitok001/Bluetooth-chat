/// Composite state of a BLE connection's secure channel, combining
/// handshake progress (owned by SecureChannelService) with the trust
/// decision (owned by TrustStoreService). Consumed by BluetoothChatService
/// and the UI layer.
enum SecureChannelState {
  idle,
  handshaking,
  awaitingTrustConfirmation,
  identityMismatch,
  established,
  failed,
}
