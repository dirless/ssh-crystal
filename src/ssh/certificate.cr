require "base64"
require "./wire"
require "./keygen"
require "./private_key"
require "./public_key"

module SSH
  # Builds and signs `ssh-ed25519-cert-v01@openssh.com` user certificates
  # per OpenSSH PROTOCOL.certkeys.
  module Certificate
    CERT_TYPE = "ssh-ed25519-cert-v01@openssh.com"

    # Standard extensions present in all user certs issued by ssh-keygen.
    # Must be in lexicographic order (SSH spec requirement).
    STANDARD_EXTENSIONS = [
      "permit-X11-forwarding",
      "permit-agent-forwarding",
      "permit-port-forwarding",
      "permit-pty",
      "permit-user-rc",
    ]

    USER_CERT = 1_u32

    # Signs *user_public_key_line* with *ca_pem* and returns the certificate
    # line (`ssh-ed25519-cert-v01@openssh.com <base64> dirless-cert`).
    #
    # - *key_id*: embedded identity string, e.g. "alice@acme"
    # - *principals*: list of Unix usernames the cert is valid for
    # - *ttl_seconds*: certificate validity duration from now
    def self.sign(
      ca_pem : String,
      user_public_key_line : String,
      key_id : String,
      principals : Array(String),
      ttl_seconds : Int64,
    ) : String
      ca = PrivateKey.parse(ca_pem)
      user_pub = PublicKey.parse_ed25519(user_public_key_line)

      now = Time.utc.to_unix.to_u64
      valid_after  = now
      valid_before = (now + ttl_seconds.to_u64)

      # The body is everything up to (but not including) the signature field.
      # We build it first, sign it, then append the signature.
      body = IO::Memory.new

      Wire.write_string(body, CERT_TYPE)
      Wire.write_string(body, Random::Secure.random_bytes(32))  # nonce
      Wire.write_string(body, user_pub.key_bytes)               # user public key
      Wire.write_uint64(body, 0_u64)                            # serial
      Wire.write_uint32(body, USER_CERT)                        # type
      Wire.write_string(body, key_id)                           # key id
      Wire.write_string(body, encode_principals(principals))    # valid principals
      Wire.write_uint64(body, valid_after)
      Wire.write_uint64(body, valid_before)
      Wire.write_string(body, "")                               # critical options (none)
      Wire.write_string(body, encode_extensions)                # standard extensions
      Wire.write_string(body, "")                               # reserved
      Wire.write_string(body, ca_public_key_blob(ca))           # CA public key

      sig = sign_with_ca(ca, body.to_slice)

      # Full cert = body + signature field
      cert = IO::Memory.new
      cert.write(body.to_slice)
      Wire.write_string(cert, sig)

      "#{CERT_TYPE} #{Base64.strict_encode(cert.to_slice)} dirless-cert"
    end

    # ── Private helpers ───────────────────────────────────────────────────────

    # Encodes the principals name-list as an SSH string-of-string-list
    # (the wire encoding of valid_principals is a `string` containing a
    # sequence of `string` entries, not a bare name-list).
    private def self.encode_principals(principals : Array(String)) : Bytes
      io = IO::Memory.new
      principals.each { |p| Wire.write_string(io, p) }
      io.to_slice
    end

    # Encodes standard extensions as an SSH string containing (name, data) pairs
    # in lexicographic order, each pair encoded as two SSH strings.
    # Flag extensions have empty data.
    private def self.encode_extensions : Bytes
      io = IO::Memory.new
      STANDARD_EXTENSIONS.each do |name|
        Wire.write_string(io, name)
        Wire.write_string(io, "")  # empty data = flag extension
      end
      io.to_slice
    end

    # Wire-format blob of the CA's Ed25519 public key (for embedding in the cert).
    private def self.ca_public_key_blob(ca : PrivateKey::Ed25519KeyPair) : Bytes
      io = IO::Memory.new
      Wire.write_string(io, "ssh-ed25519")
      Wire.write_string(io, ca.public_key)
      io.to_slice
    end

    # Builds the SSH signature structure:
    #   string "ssh-ed25519"
    #   string <64-byte Ed25519 signature over body>
    private def self.sign_with_ca(ca : PrivateKey::Ed25519KeyPair, body : Bytes) : Bytes
      raw_sig = Keygen.sign_ed25519(ca.private_seed, body)

      io = IO::Memory.new
      Wire.write_string(io, "ssh-ed25519")
      Wire.write_string(io, raw_sig)
      io.to_slice
    end
  end
end
