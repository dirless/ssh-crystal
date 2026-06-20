# ssh-crystal

Pure-Crystal SSH primitives. No subprocesses, no temp files.

- Ed25519 keypair generation via OpenSSL EVP
- OpenSSH private key PEM serialization / parsing (`-----BEGIN OPENSSH PRIVATE KEY-----`)
- SSH public key line parsing (`ssh-ed25519 AAAA...`)
- `ssh-ed25519-cert-v01@openssh.com` user certificate signing

## Installation

```yaml
dependencies:
  ssh-crystal:
    github: dirless/ssh-crystal
    version: ~> 0.1
```

## Usage

### Generate a CA keypair and sign a user certificate

```crystal
require "ssh-crystal"

# Generate a CA keypair. Returns {pem, "ssh-ed25519 AAAA... comment"}.
ca_pem, ca_pub = SSH::PrivateKey.generate("my-ca")

# Sign a user's public key for 8 hours.
cert = SSH::Certificate.sign(
  ca_pem:               ca_pem,
  user_public_key_line: "ssh-ed25519 AAAA... alice@laptop",
  key_id:               "alice@acme",
  principals:           ["alice"],
  ttl_seconds:          8 * 3600_i64,
)
# => "ssh-ed25519-cert-v01@openssh.com AAAA... dirless-cert"

File.write("/tmp/id_ed25519-cert.pub", cert)
```

Verify with `ssh-keygen -L -f /tmp/id_ed25519-cert.pub`.

### Parse an existing OpenSSH private key

```crystal
pair = SSH::PrivateKey.parse(File.read("/etc/dirless/ca.pem"))
pair.private_seed  # => Bytes (32)
pair.public_key    # => Bytes (32)
pair.comment       # => "my-ca"
```

### Parse a public key line

```crystal
key = SSH::PublicKey.parse_ed25519("ssh-ed25519 AAAA... alice@laptop")
key.key_bytes  # => Bytes (32)
key.comment    # => "alice@laptop"
```

## Modules

| Module | Purpose |
|--------|---------|
| `SSH::Wire` | RFC 4251 binary encoding (uint32/uint64/string read+write) |
| `SSH::Keygen` | Ed25519 keypair generation and signing via OpenSSL EVP |
| `SSH::PrivateKey` | OpenSSH PEM serialization and parsing |
| `SSH::PublicKey` | SSH public key line parsing |
| `SSH::Certificate` | Certificate assembly and signing |

## License

Apache-2.0
