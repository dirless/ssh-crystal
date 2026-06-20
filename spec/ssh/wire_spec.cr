require "../spec_helper"

describe SSH::Wire do
  describe "uint32 round-trip" do
    it "encodes and decodes 0" do
      io = IO::Memory.new
      SSH::Wire.write_uint32(io, 0_u32)
      io.rewind
      SSH::Wire.read_uint32(io).should eq(0_u32)
    end

    it "encodes and decodes UInt32::MAX" do
      io = IO::Memory.new
      SSH::Wire.write_uint32(io, UInt32::MAX)
      io.rewind
      SSH::Wire.read_uint32(io).should eq(UInt32::MAX)
    end

    it "is big-endian (0x01020304 → bytes 01 02 03 04)" do
      io = IO::Memory.new
      SSH::Wire.write_uint32(io, 0x01020304_u32)
      io.to_slice.should eq(Bytes[0x01, 0x02, 0x03, 0x04])
    end
  end

  describe "uint64 round-trip" do
    it "encodes and decodes a large value" do
      io = IO::Memory.new
      SSH::Wire.write_uint64(io, 0xdeadbeefcafebabe_u64)
      io.rewind
      SSH::Wire.read_uint64(io).should eq(0xdeadbeefcafebabe_u64)
    end
  end

  describe "string round-trip" do
    it "encodes and decodes an empty string" do
      io = IO::Memory.new
      SSH::Wire.write_string(io, "")
      io.rewind
      SSH::Wire.read_string_str(io).should eq("")
    end

    it "encodes and decodes a regular string" do
      io = IO::Memory.new
      SSH::Wire.write_string(io, "ssh-ed25519")
      io.rewind
      SSH::Wire.read_string_str(io).should eq("ssh-ed25519")
    end

    it "encodes string as uint32 length + raw bytes" do
      io = IO::Memory.new
      SSH::Wire.write_string(io, "hi")
      # 4-byte length (0x00 0x00 0x00 0x02) + "hi"
      io.to_slice.should eq(Bytes[0x00, 0x00, 0x00, 0x02, 0x68, 0x69])
    end
  end

  describe "name-list" do
    it "encodes a name-list as a comma-separated string" do
      io = IO::Memory.new
      SSH::Wire.write_name_list(io, ["permit-pty", "permit-user-rc"])
      io.rewind
      SSH::Wire.read_string_str(io).should eq("permit-pty,permit-user-rc")
    end
  end
end
