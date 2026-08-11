enum MessageType { text, emoji, file }

class ChatMessage {
  final String id;
  final String text;
  final String senderName;
  final bool isMine;
  final DateTime createdAt;
  final String? avatarPath;
  final MessageType type;
  final String? filePath;
  final String? fileName;

  const ChatMessage({
    required this.id,
    required this.text,
    required this.senderName,
    required this.isMine,
    required this.createdAt,
    this.avatarPath,
    required this.type,
    this.filePath,
    this.fileName,
  });
}
