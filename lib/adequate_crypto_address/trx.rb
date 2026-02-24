# frozen_string_literal: true

require "digest"

module AdequateCryptoAddress
  class Trx
    attr_reader :address, :type

    BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    BASE58_INDEX = BASE58_ALPHABET.chars.each_with_index.to_h.freeze

    PREFIX_BY_TYPE = {
      prod:   0x41, # mainnet
      test:   0xA0, # testnet (часто так в java-tron tooling)
      testnet: 0xA0
    }.freeze

    def initialize(address)
      @address = address.to_s
      @type = address_type
    end

    def valid?(type = nil)
      if type
        address_type == type.to_sym
      else
        !address_type.nil?
      end
    end

    private

    def address_type
      payload = decode_base58check_payload
      return nil unless payload
      return nil unless payload.bytesize == 21

      prefix = payload.getbyte(0)

      return :trx if prefix == PREFIX_BY_TYPE[:prod]
      return :testnet if prefix == PREFIX_BY_TYPE[:testnet]

      nil
    end

    # Возвращает payload (21 байт для TRX) или nil
    def decode_base58check_payload
      raw = base58_decode(address)
      return nil unless raw
      return nil if raw.bytesize < 5 # минимум 1 байт payload + 4 байта checksum

      payload  = raw.byteslice(0, raw.bytesize - 4)
      checksum = raw.byteslice(raw.bytesize - 4, 4)

      expected = double_sha256(payload).byteslice(0, 4)
      checksum == expected ? payload : nil
    rescue StandardError
      nil
    end

    def double_sha256(bytes)
      Digest::SHA256.digest(Digest::SHA256.digest(bytes))
    end

    # Base58 decode -> bytes (String ASCII-8BIT)
    def base58_decode(str)
      return nil if str.nil? || str.empty?

      int_val = 0
      str.each_char do |ch|
        digit = BASE58_INDEX[ch]
        return nil if digit.nil?
        int_val = int_val * 58 + digit
      end

      bytes = +""
      while int_val > 0
        int_val, mod = int_val.divmod(256)
        bytes << mod.chr
      end
      bytes = bytes.reverse

      leading_zeros = str.each_char.take_while { |c| c == "1" }.size
      ("\x00" * leading_zeros) + bytes
    end
  end

  Tron = Trx
end
