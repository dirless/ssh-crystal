require "../spec_helper"

# Generated once per spec run — keypair generation is fast (pure OpenSSL).
SPEC_CA_PEM      = SSH::PrivateKey.generate("dirless-ca-test")[0]
SPEC_USER_PUB    = SSH::PrivateKey.generate("user-key")[1]

describe SSH::Certificate do
  describe ".sign" do
    it "returns a string starting with the cert type" do
      cert = SSH::Certificate.sign(
        ca_pem: SPEC_CA_PEM,
        user_public_key_line: SPEC_USER_PUB,
        key_id: "alice@acme",
        principals: ["alice"],
        ttl_seconds: 3600_i64,
      )
      cert.should start_with("ssh-ed25519-cert-v01@openssh.com ")
      cert.should end_with(" dirless-cert")
    end

    it "produces a valid cert that ssh-keygen -L can parse" do
      cert = SSH::Certificate.sign(
        ca_pem: SPEC_CA_PEM,
        user_public_key_line: SPEC_USER_PUB,
        key_id: "alice@acme",
        principals: ["alice"],
        ttl_seconds: 3600_i64,
      )

      cert_path = File.tempname("ssh-crystal-spec", "-cert.pub")
      begin
        File.write(cert_path, cert)
        output = IO::Memory.new
        err    = IO::Memory.new
        status = Process.run(
          "ssh-keygen", args: ["-L", "-f", cert_path],
          output: output, error: err
        )
        status.success?.should be_true, "ssh-keygen -L failed: #{err}"
        output.to_s.should contain("alice@acme")
        output.to_s.should contain("alice")
        output.to_s.should contain("ssh-ed25519-cert-v01@openssh.com")
      ensure
        File.delete(cert_path) rescue nil
      end
    end

    it "embeds the correct principals" do
      cert = SSH::Certificate.sign(
        ca_pem: SPEC_CA_PEM,
        user_public_key_line: SPEC_USER_PUB,
        key_id: "bob@acme",
        principals: ["bob"],
        ttl_seconds: 86400_i64,
      )

      cert_path = File.tempname("ssh-crystal-spec", "-cert.pub")
      begin
        File.write(cert_path, cert)
        output = IO::Memory.new
        Process.run("ssh-keygen", args: ["-L", "-f", cert_path], output: output, error: Process::Redirect::Close)
        output.to_s.should contain("bob")
      ensure
        File.delete(cert_path) rescue nil
      end
    end

    it "different calls produce different certs (nonce randomness)" do
      cert1 = SSH::Certificate.sign(SPEC_CA_PEM, SPEC_USER_PUB, "alice@acme", ["alice"], 3600_i64)
      cert2 = SSH::Certificate.sign(SPEC_CA_PEM, SPEC_USER_PUB, "alice@acme", ["alice"], 3600_i64)
      cert1.should_not eq(cert2)
    end
  end
end
