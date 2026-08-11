import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';

import '../models/chat_message.dart';
import '../models/chat_profile.dart';
import '../models/secure_channel_state.dart';
import '../services/bluetooth_chat_service.dart';
import '../services/chat_storage_service.dart';
import '../services/identity_service.dart';
import '../services/security_service.dart';
import 'profile_screen.dart';
import 'safety_verification_screen.dart';

class ChatScreen extends StatefulWidget {
  const ChatScreen({super.key});

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  late final BluetoothChatService _service;
  late final ChatStorageService _storage;
  late final SecurityService _security;
  late final IdentityService _identity;
  late ChatProfile _myProfile;
  late ChatProfile _peerProfile;

  final List<ChatMessage> _messages = [];
  final TextEditingController _messageController = TextEditingController();
  late final StreamSubscription<IncomingTransfer> _incomingTransferSubscription;
  late final StreamSubscription<IncomingTextMessage> _incomingTextSubscription;
  late final StreamSubscription<SecureChannelState> _channelStateSubscription;
  late final StreamSubscription<TrustPromptEvent> _trustPromptSubscription;
  bool _isScanning = false;
  bool _isConnecting = false;
  bool _isSendingFile = false;
  SecretKey? _localStorageKey;
  SecureChannelState _channelState = SecureChannelState.idle;
  Uint8List? _myIdentityPublicKey;

  @override
  void initState() {
    super.initState();
    _service = BluetoothChatService();
    _storage = ChatStorageService();
    _security = SecurityService();
    _identity = IdentityService();
    _myProfile = const ChatProfile(id: 'me', name: 'You', isMe: true);
    _peerProfile = const ChatProfile(id: 'peer', name: 'Ava', isMe: false);

    _incomingTransferSubscription =
        _service.incomingTransfers.listen(_handleIncomingTransfer);
    _incomingTextSubscription =
        _service.incomingTextMessages.listen(_handleIncomingText);
    _channelStateSubscription =
        _service.channelStateChanges.listen(_handleChannelStateChange);
    _trustPromptSubscription =
        _service.trustPrompts.listen(_handleTrustPrompt);
    _bootstrap();
  }

  @override
  void dispose() {
    _messageController.dispose();
    _incomingTransferSubscription.cancel();
    _incomingTextSubscription.cancel();
    _channelStateSubscription.cancel();
    _trustPromptSubscription.cancel();
    _service.dispose();
    super.dispose();
  }

  Future<void> _bootstrap() async {
    await _storage.initialize();
    _localStorageKey = await _security.getLocalStorageKey();
    _myIdentityPublicKey = await _identity.getPublicKeyBytes();

    final persistedMessages = await _storage.loadMessages(_localStorageKey!);
    if (!mounted) {
      return;
    }

    setState(() {
      _messages
        ..clear()
        ..addAll(
          persistedMessages.isEmpty
              ? [
                  ChatMessage(
                    id: 'welcome',
                    text: 'Привет! Найди устройство рядом и начни общение.',
                    senderName: 'Ava',
                    isMine: false,
                    createdAt: DateTime.now(),
                    type: MessageType.text,
                  ),
                ]
              : persistedMessages,
        );
    });

    await _loadNearbyDevices();
  }

  Future<void> _persistMessages() async {
    final key = _localStorageKey ??= await _security.getLocalStorageKey();
    await _storage.saveMessages(_messages, key);
  }

  void _handleChannelStateChange(SecureChannelState state) {
    if (!mounted) {
      return;
    }
    setState(() => _channelState = state);

    if (state == SecureChannelState.established) {
      setState(() {
        _messages.add(
          ChatMessage(
            id: DateTime.now().toIso8601String(),
            text:
                'Защищённое соединение установлено с ${_service.connectedDevice?.name ?? 'устройством'}',
            senderName: 'System',
            isMine: false,
            createdAt: DateTime.now(),
            type: MessageType.text,
          ),
        );
      });
      _persistMessages();
    }
  }

  Future<void> _handleTrustPrompt(TrustPromptEvent event) async {
    if (!mounted) {
      return;
    }

    final accepted = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        title: Text(event.isChanged ? 'Ключ устройства изменился' : 'Новое устройство'),
        content: Text(
          event.isChanged
              ? 'У устройства "${event.displayName ?? event.bleId}" изменился ключ безопасности. '
                  'Это может значить переустановку приложения — или атаку. Продолжить, только если вы уверены.'
              : 'Устройство "${event.displayName ?? event.bleId}" подключается впервые. Доверять и начать общение?',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Отмена'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: Text(event.isChanged ? 'Всё равно продолжить' : 'Доверять'),
          ),
        ],
      ),
    );

    await _service.respondToTrustPrompt(accepted ?? false);
  }

  Future<void> _loadNearbyDevices() async {
    setState(() => _isScanning = true);
    await _service.initialize();
    await _service.startScanning();
    if (mounted) {
      setState(() => _isScanning = false);
    }
  }

  Future<void> _connectToDevice(BluetoothDeviceInfo device) async {
    setState(() => _isConnecting = true);
    await _service.connectToDevice(device);

    if (mounted) {
      setState(() => _isConnecting = false);
    }
  }

  Future<void> _pickAvatar() async {
    final picker = ImagePicker();
    final pickedFile = await picker.pickImage(source: ImageSource.gallery);
    if (pickedFile == null) {
      return;
    }

    if (mounted) {
      setState(() {
        _myProfile = _myProfile.copyWith(avatarPath: pickedFile.path);
      });
    }
  }

  Future<void> _pickFile() async {
    final picker = ImagePicker();
    final pickedFile = await picker.pickImage(source: ImageSource.gallery);
    if (pickedFile == null) {
      return;
    }

    setState(() => _isSendingFile = true);

    try {
      await _service.sendFile(pickedFile.path, fileName: pickedFile.name);

      if (mounted) {
        setState(() {
          _messages.add(
            ChatMessage(
              id: DateTime.now().toIso8601String(),
              text: 'Файл отправлен',
              senderName: _myProfile.name,
              isMine: true,
              createdAt: DateTime.now(),
              avatarPath: _myProfile.avatarPath,
              type: MessageType.file,
              filePath: pickedFile.path,
              fileName: pickedFile.name,
            ),
          );
        });
        await _persistMessages();
      }
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Не удалось отправить файл: $error')),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isSendingFile = false);
      }
    }
  }

  void _handleIncomingTransfer(IncomingTransfer transfer) {
    if (!mounted) {
      return;
    }

    setState(() {
      _messages.add(
        ChatMessage(
          id: DateTime.now().toIso8601String(),
          text: 'Получен файл',
          senderName: 'Remote',
          isMine: false,
          createdAt: DateTime.now(),
          type: MessageType.file,
          filePath: transfer.filePath,
          fileName: transfer.fileName,
        ),
      );
    });
    _persistMessages();
  }

  void _handleIncomingText(IncomingTextMessage message) {
    if (!mounted) {
      return;
    }

    setState(() {
      _messages.add(
        ChatMessage(
          id: DateTime.now().toIso8601String(),
          text: message.text,
          senderName: message.senderName,
          isMine: false,
          createdAt: DateTime.now(),
          type: MessageType.text,
        ),
      );
    });
    _persistMessages();
  }

  Future<void> _sendMessage([String? customText]) async {
    final text = (customText ?? _messageController.text).trim();
    if (text.isEmpty) {
      return;
    }

    final message = ChatMessage(
      id: DateTime.now().toIso8601String(),
      text: text,
      senderName: _myProfile.name,
      isMine: true,
      createdAt: DateTime.now(),
      avatarPath: _myProfile.avatarPath,
      type: customText == null ? MessageType.text : MessageType.emoji,
    );

    if (mounted) {
      setState(() {
        _messages.add(message);
        _messageController.clear();
      });
      await _persistMessages();
    }

    await _service.sendMessage(text);

    if (_service.connectedDevice != null && mounted) {
      setState(() {
        _messages.add(
          ChatMessage(
            id: '${DateTime.now().microsecondsSinceEpoch}-reply',
            text: 'Отлично! Я получил: $text',
            senderName: _peerProfile.name,
            isMine: false,
            createdAt: DateTime.now(),
            avatarPath: _peerProfile.avatarPath,
            type: MessageType.text,
          ),
        );
      });
      await _persistMessages();
    }
  }

  Widget _avatarFor(ChatProfile profile) {
    if (profile.avatarPath != null) {
      return CircleAvatar(
        radius: 20,
        backgroundImage: FileImage(File(profile.avatarPath!)),
      );
    }

    return CircleAvatar(
      radius: 20,
      backgroundColor:
          profile.isMe ? const Color(0xFF5C6DFF) : const Color(0xFF2FC4A0),
      child: Text(profile.name.substring(0, 1),
          style: const TextStyle(color: Colors.white)),
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      backgroundColor: const Color(0xFFF5F7FF),
      appBar: AppBar(
        backgroundColor: const Color(0xFFF5F7FF),
        elevation: 0,
        title: const Text('Nearby Chat',
            style: TextStyle(fontWeight: FontWeight.w700)),
        actions: [
          if (_channelState == SecureChannelState.established &&
              _myIdentityPublicKey != null)
            IconButton(
              onPressed: () {
                final peerKey = _service.connectedPeerIdentityPublicKey;
                final myKey = _myIdentityPublicKey;
                if (peerKey == null || myKey == null) {
                  return;
                }
                Navigator.of(context).push(
                  MaterialPageRoute(
                    builder: (_) => SafetyVerificationScreen(
                      myIdentityPublicKey: myKey,
                      peerIdentityPublicKey: peerKey,
                    ),
                  ),
                );
              },
              icon: const Icon(Icons.verified_user_outlined),
              tooltip: 'Проверить безопасность',
            ),
          IconButton(
            onPressed: _pickAvatar,
            icon: const Icon(Icons.account_circle_outlined),
            tooltip: 'Выбрать аватар',
          ),
        ],
      ),
      body: Column(
        children: [
          _buildHeroCard(theme),
          _buildDeviceSection(),
          Expanded(child: _buildMessages()),
          _buildMessageComposer(),
        ],
      ),
    );
  }

  Widget _buildHeroCard(ThemeData theme) {
    return Container(
      margin: const EdgeInsets.fromLTRB(16, 8, 16, 12),
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          colors: [Color(0xFF7B61FF), Color(0xFF1FCEB4)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(28),
        boxShadow: [
          BoxShadow(
              color: const Color(0xFF7B61FF).withOpacity(0.25),
              blurRadius: 20,
              offset: const Offset(0, 10)),
        ],
      ),
      child: Row(
        children: [
          GestureDetector(
            onTap: () async {
              await Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => ProfileScreen(
                    profile: _myProfile,
                    onProfileChanged: (profile) {
                      setState(() => _myProfile = profile);
                    },
                  ),
                ),
              );
            },
            child: Container(
              padding: const EdgeInsets.all(2),
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(color: Colors.white, width: 2),
              ),
              child: _avatarFor(_myProfile),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(_myProfile.name,
                    style: const TextStyle(
                        color: Colors.white,
                        fontSize: 18,
                        fontWeight: FontWeight.w800)),
                const SizedBox(height: 4),
                Text(
                  _service.connectedDevice == null
                      ? 'Связь не активна'
                      : 'Подключено к ${_service.connectedDevice!.name}',
                  style: const TextStyle(color: Colors.white70, fontSize: 13),
                ),
              ],
            ),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
            decoration: BoxDecoration(
                color: Colors.white.withOpacity(0.18),
                borderRadius: BorderRadius.circular(999)),
            child: Row(
              children: [
                if (_isScanning) ...[
                  const SizedBox(
                      width: 12,
                      height: 12,
                      child: CircularProgressIndicator(
                          strokeWidth: 2, color: Colors.white)),
                  const SizedBox(width: 6),
                ],
                Text(_isScanning ? 'Поиск' : 'Live',
                    style: const TextStyle(
                        color: Colors.white, fontWeight: FontWeight.w700)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDeviceSection() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
      child: Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.circular(24),
          boxShadow: [
            BoxShadow(
                color: Colors.black.withOpacity(0.05),
                blurRadius: 16,
                offset: const Offset(0, 8))
          ],
        ),
        child: Column(
          children: [
            Row(
              children: [
                const Text('Поблизости',
                    style:
                        TextStyle(fontWeight: FontWeight.w800, fontSize: 15)),
                const Spacer(),
                TextButton.icon(
                  onPressed: _loadNearbyDevices,
                  icon: const Icon(Icons.refresh_rounded, size: 18),
                  label: const Text('Обновить'),
                ),
              ],
            ),
            if (_service.discoveredDevices.isEmpty)
              Padding(
                padding: const EdgeInsets.only(top: 8, bottom: 4),
                child: Text('Список устройств появится после поиска',
                    style: TextStyle(color: Colors.grey.shade600)),
              )
            else
              ..._service.discoveredDevices.map(
                (device) => Padding(
                  padding: const EdgeInsets.only(top: 6),
                  child: Row(
                    children: [
                      Container(
                        width: 38,
                        height: 38,
                        decoration: BoxDecoration(
                          color: const Color(0xFFF0EDFF),
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: const Icon(Icons.bluetooth_rounded,
                            color: Color(0xFF7B61FF), size: 20),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(device.name,
                                style: const TextStyle(
                                    fontWeight: FontWeight.w700)),
                            Text('Bluetooth LE',
                                style: TextStyle(
                                    color: Colors.grey.shade600, fontSize: 12)),
                          ],
                        ),
                      ),
                      _isConnecting
                          ? const SizedBox(
                              width: 20,
                              height: 20,
                              child: CircularProgressIndicator(strokeWidth: 2))
                          : TextButton(
                              onPressed: () => _connectToDevice(device),
                              child: const Text('Подключить'),
                            ),
                    ],
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildMessages() {
    return ListView.separated(
      padding: const EdgeInsets.fromLTRB(16, 6, 16, 8),
      itemCount: _messages.length,
      separatorBuilder: (_, __) => const SizedBox(height: 10),
      itemBuilder: (context, index) {
        final message = _messages[index];
        return AnimatedContainer(
          duration: const Duration(milliseconds: 240),
          curve: Curves.easeOutCubic,
          child: Align(
            alignment:
                message.isMine ? Alignment.centerRight : Alignment.centerLeft,
            child: Row(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                if (!message.isMine) ...[
                  _avatarFor(ChatProfile(
                      id: message.senderName,
                      name: message.senderName,
                      avatarPath: message.avatarPath,
                      isMe: false)),
                  const SizedBox(width: 8),
                ],
                ConstrainedBox(
                  constraints: BoxConstraints(
                      maxWidth: MediaQuery.of(context).size.width * 0.74),
                  child: Container(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 14, vertical: 12),
                    decoration: BoxDecoration(
                      color: message.isMine
                          ? const Color(0xFF7B61FF)
                          : Colors.white,
                      borderRadius: BorderRadius.circular(20),
                      boxShadow: [
                        BoxShadow(
                            color: Colors.black.withOpacity(0.05),
                            blurRadius: 10,
                            offset: const Offset(0, 4))
                      ],
                    ),
                    child: message.type == MessageType.file
                        ? Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Icon(
                                Icons.attach_file_rounded,
                                color: message.isMine
                                    ? Colors.white
                                    : const Color(0xFF7B61FF),
                                size: 18,
                              ),
                              const SizedBox(width: 8),
                              Flexible(
                                child: Text(
                                  message.fileName ?? message.text,
                                  style: TextStyle(
                                    color: message.isMine
                                        ? Colors.white
                                        : Colors.black87,
                                    fontSize: 14,
                                  ),
                                ),
                              ),
                            ],
                          )
                        : Text(
                            message.text,
                            style: TextStyle(
                                color: message.isMine
                                    ? Colors.white
                                    : Colors.black87,
                                fontSize: 15),
                          ),
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildMessageComposer() {
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
        child: Column(
          children: [
            Row(
              children: [
                _emojiButton('😊'),
                _emojiButton('😂'),
                _emojiButton('❤️'),
                _emojiButton('🔥'),
                _emojiButton('👍'),
              ],
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                IconButton(
                  onPressed: _pickFile,
                  icon: _isSendingFile
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : const Icon(Icons.attach_file_rounded),
                  tooltip: 'Отправить файл',
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Container(
                    padding:
                        const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(24),
                      boxShadow: [
                        BoxShadow(
                            color: Colors.black.withOpacity(0.06),
                            blurRadius: 12,
                            offset: const Offset(0, 6))
                      ],
                    ),
                    child: Row(
                      children: [
                        Expanded(
                          child: TextField(
                            controller: _messageController,
                            decoration: const InputDecoration(
                              hintText: 'Введите сообщение',
                              border: InputBorder.none,
                              contentPadding:
                                  EdgeInsets.symmetric(horizontal: 8),
                            ),
                            onSubmitted: (_) => _sendMessage(),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Container(
                          decoration: BoxDecoration(
                            gradient: const LinearGradient(
                                colors: [Color(0xFF7B61FF), Color(0xFF1FCEB4)]),
                            borderRadius: BorderRadius.circular(18),
                          ),
                          child: IconButton(
                            onPressed: _channelState == SecureChannelState.established
                                ? () => _sendMessage()
                                : null,
                            icon: const Icon(Icons.send_rounded),
                            color: Colors.white,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _emojiButton(String emoji) {
    return Expanded(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 4),
        child: InkWell(
          onTap: () => _sendMessage(emoji),
          borderRadius: BorderRadius.circular(14),
          child: Container(
            padding: const EdgeInsets.symmetric(vertical: 8),
            decoration: BoxDecoration(
              color: const Color(0xFFF2EEFF),
              borderRadius: BorderRadius.circular(14),
            ),
            child: Center(
                child: Text(emoji, style: const TextStyle(fontSize: 18))),
          ),
        ),
      ),
    );
  }
}
