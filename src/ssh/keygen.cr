require "openssl"

module SSH
  # Additional LibCrypto bindings needed for Ed25519 — the Crystal stdlib only
  # covers RSA/EC/digest operations. EVP_MD_CTX_new/free are already bound by
  # the stdlib so we reuse LibCrypto directly for those.
  @[Link("crypto")]
  lib LibCryptoEd25519
    EVP_PKEY_ED25519 = 1087

    fun EVP_PKEY_CTX_new_id(id : Int32, engine : Void*) : Void*
    fun EVP_PKEY_keygen_init(ctx : Void*) : Int32
    fun EVP_PKEY_keygen(ctx : Void*, pkey : Void**) : Int32
    fun EVP_PKEY_CTX_free(ctx : Void*) : Void
    fun EVP_PKEY_free(pkey : Void*) : Void

    fun EVP_PKEY_get_raw_private_key(pkey : Void*, priv : UInt8*, len : LibC::SizeT*) : Int32
    fun EVP_PKEY_get_raw_public_key(pkey : Void*, pub : UInt8*, len : LibC::SizeT*) : Int32

    fun EVP_PKEY_new_raw_private_key(type : Int32, engine : Void*, priv : UInt8*, len : LibC::SizeT) : Void*

    # DigestSign with the EVP_MD_CTX type from the Crystal stdlib.
    fun EVP_DigestSignInit(ctx : LibCrypto::EVP_MD_CTX, pctx : Void**, type : Void*, engine : Void*, pkey : Void*) : Int32
    fun EVP_DigestSign(ctx : LibCrypto::EVP_MD_CTX, sig : UInt8*, siglen : LibC::SizeT*, tbs : UInt8*, tbslen : LibC::SizeT) : Int32
  end

  module Keygen
    ED25519_KEY_SIZE = 32

    # Generates an Ed25519 keypair via OpenSSL EVP.
    # Returns `{private_seed_bytes, public_key_bytes}` — both 32 bytes.
    def self.generate_ed25519 : {Bytes, Bytes}
      ctx = LibCryptoEd25519.EVP_PKEY_CTX_new_id(LibCryptoEd25519::EVP_PKEY_ED25519, nil)
      raise "EVP_PKEY_CTX_new_id failed" if ctx.null?

      pkey = Pointer(Void).null
      begin
        raise "EVP_PKEY_keygen_init failed" if LibCryptoEd25519.EVP_PKEY_keygen_init(ctx) != 1
        raise "EVP_PKEY_keygen failed" if LibCryptoEd25519.EVP_PKEY_keygen(ctx, pointerof(pkey)) != 1

        priv_len = LibC::SizeT.new(ED25519_KEY_SIZE)
        priv_buf = Bytes.new(ED25519_KEY_SIZE)
        raise "EVP_PKEY_get_raw_private_key failed" if
          LibCryptoEd25519.EVP_PKEY_get_raw_private_key(pkey, priv_buf.to_unsafe, pointerof(priv_len)) != 1

        pub_len = LibC::SizeT.new(ED25519_KEY_SIZE)
        pub_buf = Bytes.new(ED25519_KEY_SIZE)
        raise "EVP_PKEY_get_raw_public_key failed" if
          LibCryptoEd25519.EVP_PKEY_get_raw_public_key(pkey, pub_buf.to_unsafe, pointerof(pub_len)) != 1

        {priv_buf, pub_buf}
      ensure
        LibCryptoEd25519.EVP_PKEY_free(pkey) unless pkey.null?
        LibCryptoEd25519.EVP_PKEY_CTX_free(ctx)
      end
    end

    # Signs *message* with *private_seed_bytes* (32 bytes) using Ed25519.
    # Returns a 64-byte signature.
    def self.sign_ed25519(private_seed_bytes : Bytes, message : Bytes) : Bytes
      pkey = LibCryptoEd25519.EVP_PKEY_new_raw_private_key(
        LibCryptoEd25519::EVP_PKEY_ED25519, nil,
        private_seed_bytes.to_unsafe, private_seed_bytes.size
      )
      raise "EVP_PKEY_new_raw_private_key failed" if pkey.null?

      # Reuse the EVP_MD_CTX_new/free already bound by Crystal's stdlib.
      md_ctx = LibCrypto.evp_md_ctx_new
      raise "EVP_MD_CTX_new failed" if md_ctx.null?

      begin
        raise "EVP_DigestSignInit failed" if
          LibCryptoEd25519.EVP_DigestSignInit(md_ctx, nil, nil, nil, pkey) != 1

        sig_len = LibC::SizeT.new(0)
        raise "EVP_DigestSign (len query) failed" if
          LibCryptoEd25519.EVP_DigestSign(md_ctx, nil, pointerof(sig_len), message.to_unsafe, message.size) != 1

        sig_buf = Bytes.new(sig_len)
        raise "EVP_DigestSign failed" if
          LibCryptoEd25519.EVP_DigestSign(md_ctx, sig_buf.to_unsafe, pointerof(sig_len), message.to_unsafe, message.size) != 1

        sig_buf[0, sig_len]
      ensure
        LibCrypto.evp_md_ctx_free(md_ctx)
        LibCryptoEd25519.EVP_PKEY_free(pkey)
      end
    end
  end
end
