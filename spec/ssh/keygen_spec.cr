require "../spec_helper"

describe SSH::Keygen do
  describe ".generate_ed25519" do
    it "returns 32-byte private seed and 32-byte public key" do
      priv, pub = SSH::Keygen.generate_ed25519
      priv.size.should eq(32)
      pub.size.should eq(32)
    end

    it "produces a different keypair on each call" do
      priv1, pub1 = SSH::Keygen.generate_ed25519
      priv2, pub2 = SSH::Keygen.generate_ed25519
      priv1.should_not eq(priv2)
      pub1.should_not eq(pub2)
    end
  end

  describe ".sign_ed25519" do
    it "produces a 64-byte signature" do
      priv, _ = SSH::Keygen.generate_ed25519
      sig = SSH::Keygen.sign_ed25519(priv, "hello".to_slice)
      sig.size.should eq(64)
    end

    it "produces different signatures for different messages" do
      priv, _ = SSH::Keygen.generate_ed25519
      sig1 = SSH::Keygen.sign_ed25519(priv, "msg1".to_slice)
      sig2 = SSH::Keygen.sign_ed25519(priv, "msg2".to_slice)
      sig1.should_not eq(sig2)
    end
  end
end
