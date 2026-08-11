class TrustedPeer {
  final String identityPublicKeyBase64;
  final String? bleId;
  final String? displayName;
  final DateTime firstSeen;
  final DateTime lastSeen;
  final bool verified;

  const TrustedPeer({
    required this.identityPublicKeyBase64,
    this.bleId,
    this.displayName,
    required this.firstSeen,
    required this.lastSeen,
    required this.verified,
  });
}

/// Result of comparing a freshly-authenticated peer identity against what's
/// already known locally.
class TrustDecision {
  final bool isNewDevice;
  final bool isChanged;
  final String? previousIdentityPublicKeyBase64;

  const TrustDecision({
    required this.isNewDevice,
    required this.isChanged,
    this.previousIdentityPublicKeyBase64,
  });
}

/// Pure decision function (no I/O) so the trust-on-first-use policy can be
/// unit tested without a database.
///
/// [identityKnown] is true if a `trusted_peers` row already exists for the
/// exact identity public key just authenticated in the handshake.
/// [conflictingBleIdIdentity] is the identity public key (base64) previously
/// recorded for this connection's BLE id, if any, and if it differs from the
/// identity that just authenticated.
TrustDecision evaluateTrustDecision({
  required bool identityKnown,
  required String? conflictingBleIdIdentity,
}) {
  if (identityKnown) {
    return const TrustDecision(isNewDevice: false, isChanged: false);
  }
  if (conflictingBleIdIdentity != null) {
    return TrustDecision(
      isNewDevice: false,
      isChanged: true,
      previousIdentityPublicKeyBase64: conflictingBleIdIdentity,
    );
  }
  return const TrustDecision(isNewDevice: true, isChanged: false);
}
