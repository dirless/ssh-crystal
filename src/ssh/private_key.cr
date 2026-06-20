require "base64"
require "./wire"
require "./keygen"

module SSH
  # Serializes and deserializes OpenSSH private key PEM files
  # (`-----BEGIN OPENSSH PRIVATE KEY-----`).
  # Only unencrypted Ed25519 keys are supported.
  module PrivateKey
    OPENSSH_MAGIC = "openssh-key-v1\0"
    PEM_LABEL     = "OPENSSH PRIVATE KEY"

    record Ed25519KeyPair,
      # 32-byte Ed25519 seed (the "private key" in OpenSSH terminology).
      private_seed : Bytes,
      # 32-byte Ed25519 public key.
      public_key : Bytes,
      comment : String

    # Generates a new Ed25519 keypair and returns it serialized as an OpenSSH
    # PEM string and the single-line public key string.
    #
    # *comment* is embedded in the private key and appended to the public key line.
    #
    # Returns `{pem, public_key_line}`.
    def self.generate(comment : String = "") : {String, String}
      priv, pub = Keygen.generate_ed25519
      pair = Ed25519KeyPair.new(private_seed: priv, public_key: pub, comment: comment)
      {serialize(pair), public_key_line(pair)}
    end

    # Parses an OpenSSH PEM string and returns the keypair.
    def self.parse(pem : String) : Ed25519KeyPair
      b64 = pem
        .lines
        .reject { |l| l.starts_with?("-----") }
        .join
      raw = Base64.decode(b64)
      deserialize(raw)
    end

    # Returns the `ssh-ed25519 <base64> <comment>` public key line.
    def self.public_key_line(pair : Ed25519KeyPair) : String
      blob = public_key_blob(pair.public_key)
      b64 = Base64.strict_encode(blob)
      comment = pair.comment.empty? ? "" : " #{pair.comment}"
      "ssh-ed25519 #{b64}#{comment}"
    end

    # ── Private helpers ───────────────────────────────────────────────────────

    private def self.serialize(pair : Ed25519KeyPair) : String
      pub_blob = public_key_blob(pair.public_key)

      # Private key blob (the inner "body" that holds the actual key material).
      priv_blob = IO::Memory.new
      check = Random::Secure.rand(UInt32::MAX).to_u32
      Wire.write_uint32(priv_blob, check)
      Wire.write_uint32(priv_blob, check)
      Wire.write_string(priv_blob, "ssh-ed25519")
      # Public key field inside the private blob
      Wire.write_string(priv_blob, pair.public_key)
      # Private key field: seed (32 bytes) || public key (32 bytes)
      Wire.write_string(priv_blob, pair.private_seed + pair.public_key)
      Wire.write_string(priv_blob, pair.comment)
      # Padding: bytes 1, 2, 3, … until length is a multiple of 8
      pad_byte = 1_u8
      while priv_blob.size % 8 != 0
        priv_blob.write_byte(pad_byte)
        pad_byte += 1
      end

      # Outer container
      outer = IO::Memory.new
      outer.print(OPENSSH_MAGIC)
      Wire.write_string(outer, "none")     # ciphername
      Wire.write_string(outer, "none")     # kdfname
      Wire.write_string(outer, "")        # kdfoptions
      Wire.write_uint32(outer, 1_u32)     # num_keys
      Wire.write_string(outer, pub_blob)
      Wire.write_string(outer, priv_blob.to_slice)

      pem_wrap(Base64.strict_encode(outer.to_slice), PEM_LABEL)
    end

    private def self.deserialize(raw : Bytes) : Ed25519KeyPair
      io = IO::Memory.new(raw)

      magic = Bytes.new(OPENSSH_MAGIC.bytesize)
      io.read_fully(magic)
      raise "not an OpenSSH private key" unless String.new(magic) == OPENSSH_MAGIC

      ciphername = Wire.read_string_str(io)
      raise "encrypted OpenSSH keys are not supported (cipher: #{ciphername})" unless ciphername == "none"

      kdfname = Wire.read_string_str(io)
      raise "encrypted OpenSSH keys are not supported (kdf: #{kdfname})" unless kdfname == "none"
      Wire.read_string(io) # kdfoptions

      num_keys = Wire.read_uint32(io)
      raise "only single-key OpenSSH files are supported" unless num_keys == 1

      outer_pub_blob = Wire.read_string(io)

      priv_blob = IO::Memory.new(Wire.read_string(io))
      check1 = Wire.read_uint32(priv_blob)
      check2 = Wire.read_uint32(priv_blob)
      raise "OpenSSH private key integrity check failed" unless check1 == check2

      key_type = Wire.read_string_str(priv_blob)
      raise "expected ssh-ed25519, got #{key_type}" unless key_type == "ssh-ed25519"

      pub_key  = Wire.read_string(priv_blob).dup                # 32-byte public key
      raise "Ed25519 public key wrong size (#{pub_key.size})" unless pub_key.size == 32
      priv_raw = Wire.read_string(priv_blob).dup                # seed (32) || pubkey (32)
      comment  = Wire.read_string_str(priv_blob)

      raise "Ed25519 private key blob wrong size (#{priv_raw.size})" unless priv_raw.size == 64
      raise "Ed25519 key inconsistency: public key copies do not agree" unless priv_raw[32, 32] == pub_key
      raise "Ed25519 key inconsistency: outer public key does not match inner" unless outer_pub_blob == public_key_blob(pub_key)

      # Verify padding integrity: bytes must be 1, 2, 3, … (not just zero-fill)
      pad_byte = 1_u8
      while priv_blob.pos < priv_blob.size
        b = priv_blob.read_byte || raise "truncated OpenSSH private key padding"
        raise "OpenSSH private key padding invalid" unless b == pad_byte
        pad_byte += 1
      end

      Ed25519KeyPair.new(
        private_seed: priv_raw[0, 32],
        public_key:   pub_key,
        comment:      comment,
      )
    end

    # Wire-format blob for an Ed25519 public key: "ssh-ed25519" + 32-byte pubkey.
    private def self.public_key_blob(pub : Bytes) : Bytes
      io = IO::Memory.new
      Wire.write_string(io, "ssh-ed25519")
      Wire.write_string(io, pub)
      io.to_slice
    end

    private def self.pem_wrap(b64 : String, label : String) : String
      lines = b64.chars.each_slice(70).map(&.join).to_a
      String.build do |s|
        s << "-----BEGIN #{label}-----\n"
        lines.each { |l| s << l << "\n" }
        s << "-----END #{label}-----\n"
      end
    end
  end
end
