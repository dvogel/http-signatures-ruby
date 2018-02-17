require "openssl"

module HttpSignatures
  module Algorithm
    class Rsa

      def initialize(digest_name)
        @digest_name = digest_name
        @digest = OpenSSL::Digest.new(digest_name)
      end

      def name
        "rsa-#{@digest_name}"
      end

      def sign(key, data)
        pk = OpenSSL::PKey.read(key)
        pk.sign(@digest, data)
      rescue OpenSSL::PKey::PKeyError
        nil
      end

    end
  end
end
