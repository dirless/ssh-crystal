require "base64"
require "./wire"

module SSH
  # Parses SSH public key lines (`ssh-ed25519 AAAA... comment`).
  module PublicKey
    record Ed25519PublicKey,
      key_bytes : Bytes,  # 32 raw bytes
      comment : String

    # Parses a single `ssh-ed25519 <base64> [comment]` line.
    # Raises if the line is malformed or not an Ed25519 key.
    def self.parse_ed25519(line : String) : Ed25519PublicKey
      parts = line.strip.split(/\s+/, 3)
      raise "invalid public key line: expected at least 2 fields" if parts.size < 2
      raise "not an Ed25519 public key (type: #{parts[0]})" unless parts[0] == "ssh-ed25519"

      blob = Base64.decode(parts[1]) rescue raise "invalid base64 in public key"
      io = IO::Memory.new(blob)

      key_type = Wire.read_string_str(io)
      raise "public key blob type mismatch: #{key_type}" unless key_type == "ssh-ed25519"

      key_bytes = Wire.read_string(io).dup
      raise "Ed25519 public key wrong size (#{key_bytes.size})" unless key_bytes.size == 32

      Ed25519PublicKey.new(key_bytes: key_bytes, comment: parts[2]? || "")
    end
  end
end
