module SSH
  # SSH binary wire format helpers (RFC 4251).
  # All multi-byte integers are big-endian.
  module Wire
    # ── Writers ──────────────────────────────────────────────────────────────

    def self.write_uint32(io : IO, v : UInt32) : Nil
      io.write_bytes(v, IO::ByteFormat::BigEndian)
    end

    def self.write_uint64(io : IO, v : UInt64) : Nil
      io.write_bytes(v, IO::ByteFormat::BigEndian)
    end

    # Encodes *bytes* as an SSH "string": uint32 length followed by raw bytes.
    def self.write_string(io : IO, bytes : Bytes) : Nil
      write_uint32(io, bytes.size.to_u32)
      io.write(bytes)
    end

    def self.write_string(io : IO, s : String) : Nil
      write_string(io, s.to_slice)
    end

    # Encodes a name-list as an SSH string of comma-separated names.
    def self.write_name_list(io : IO, names : Array(String)) : Nil
      write_string(io, names.join(","))
    end

    # ── Readers ───────────────────────────────────────────────────────────────

    def self.read_uint32(io : IO) : UInt32
      io.read_bytes(UInt32, IO::ByteFormat::BigEndian)
    end

    def self.read_uint64(io : IO) : UInt64
      io.read_bytes(UInt64, IO::ByteFormat::BigEndian)
    end

    def self.read_string(io : IO) : Bytes
      len = read_uint32(io)
      raise "SSH wire: string length #{len} exceeds 64 MiB" if len > 64 * 1024 * 1024
      buf = Bytes.new(len)
      io.read_fully(buf)
      buf
    end

    def self.read_string_str(io : IO) : String
      String.new(read_string(io))
    end
  end
end
