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
