require "../spec_helper"

describe SSH::PrivateKey do
  describe ".generate" do
    it "returns a PEM string and a public key line" do
      pem, pub_line = SSH::PrivateKey.generate("test-comment")
      pem.should contain("-----BEGIN OPENSSH PRIVATE KEY-----")
      pem.should contain("-----END OPENSSH PRIVATE KEY-----")
      pub_line.should start_with("ssh-ed25519 ")
      pub_line.should end_with(" test-comment")
    end

    it "round-trips through parse" do
      pem, _ = SSH::PrivateKey.generate("round-trip")
      pair = SSH::PrivateKey.parse(pem)
      pair.private_seed.size.should eq(32)
      pair.public_key.size.should eq(32)
      pair.comment.should eq("round-trip")
    end

    it "preserves the public key between generate and parse" do
      pem, pub_line = SSH::PrivateKey.generate("check-pubkey")
      pair = SSH::PrivateKey.parse(pem)
      # The public key in the PEM must match the one in the public key line.
      reparsed_pub = SSH::PublicKey.parse_ed25519(pub_line)
      pair.public_key.should eq(reparsed_pub.key_bytes)
    end

    it "produces different keypairs on each call" do
      pem1, _ = SSH::PrivateKey.generate
      pem2, _ = SSH::PrivateKey.generate
      pem1.should_not eq(pem2)
    end
  end

  describe ".parse" do
    it "raises on an encrypted private key" do
      # Minimal fake PEM with ciphername != "none" — parse will fail at that check.
      # We just verify the error message is actionable.
      expect_raises(Exception, /encrypted/) do
        # Build a minimal blob with ciphername = "aes256-ctr"
        outer = IO::Memory.new
        outer.print("openssh-key-v1\0")
        SSH::Wire.write_string(outer, "aes256-ctr")  # ciphername
        SSH::Wire.write_string(outer, "bcrypt")       # kdfname
        SSH::Wire.write_string(outer, "")             # kdfoptions
        SSH::Wire.write_uint32(outer, 1_u32)
        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
              Base64.strict_encode(outer.to_slice) + "\n" +
              "-----END OPENSSH PRIVATE KEY-----\n"
        SSH::PrivateKey.parse(pem)
      end
    end
  end
end
