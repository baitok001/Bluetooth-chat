class ChatProfile {
  final String id;
  final String name;
  final String? avatarPath;
  final bool isMe;

  const ChatProfile({
    required this.id,
    required this.name,
    this.avatarPath,
    required this.isMe,
  });

  ChatProfile copyWith({
    String? id,
    String? name,
    String? avatarPath,
    bool? isMe,
  }) {
    return ChatProfile(
      id: id ?? this.id,
      name: name ?? this.name,
      avatarPath: avatarPath ?? this.avatarPath,
      isMe: isMe ?? this.isMe,
    );
  }
}
