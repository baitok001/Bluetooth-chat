import 'package:bluetooth_chat_app/models/trusted_peer.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('evaluateTrustDecision', () {
    test('known identity is neither new nor changed', () {
      final decision = evaluateTrustDecision(
        identityKnown: true,
        conflictingBleIdIdentity: null,
      );
      expect(decision.isNewDevice, isFalse);
      expect(decision.isChanged, isFalse);
    });

    test('unknown identity with no ble-id conflict is new', () {
      final decision = evaluateTrustDecision(
        identityKnown: false,
        conflictingBleIdIdentity: null,
      );
      expect(decision.isNewDevice, isTrue);
      expect(decision.isChanged, isFalse);
    });

    test('unknown identity but ble-id previously belonged to another '
        'identity is a change, not new', () {
      final decision = evaluateTrustDecision(
        identityKnown: false,
        conflictingBleIdIdentity: 'old-key-base64',
      );
      expect(decision.isNewDevice, isFalse);
      expect(decision.isChanged, isTrue);
      expect(decision.previousIdentityPublicKeyBase64, 'old-key-base64');
    });
  });
}
