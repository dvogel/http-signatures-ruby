require "net/http"
require "time"

RSpec.describe HttpSignatures::Verifier do

  DATE = "Fri, 01 Aug 2014 13:44:32 -0700"
  DATE_DIFFERENT = "Fri, 01 Aug 2014 13:44:33 -0700"

  subject(:verifier) { HttpSignatures::Verifier.new(key_store: key_store) }
  let(:key_store) { HttpSignatures::KeyStore.new("pda" => "secret") }
  let(:message) { Net::HTTP::Get.new("/path?query=123", headers) }
  let(:headers) { {"Date" => DATE, "Signature" => signature_header} }

  let(:signature_header) do
    'keyId="%s",algorithm="%s",headers="%s",signature="%s"' % [
      "pda",
      "hmac-sha256",
      "(request-target) date",
      "cS2VvndvReuTLy52Ggi4j6UaDqGm9hMb4z0xJZ6adqU=",
    ]
  end

  it "verifies a valid message" do
    expect(verifier.valid?(message)).to eq(true)
  end

  it "rejects message with missing headers" do
    headers.clear
    expect(verifier.valid?(message)).to eq(false)
  end

  it "rejects message with tampered path" do
    message.path << "x"
    expect(verifier.valid?(message)).to eq(false)
  end

  it "rejects message with tampered date" do
    message["Date"] = DATE_DIFFERENT
    expect(verifier.valid?(message)).to eq(false)
  end

  it "rejects message with tampered signature" do
    message["Signature"] = message["Signature"].sub('signature="', 'signature="x')
    expect(verifier.valid?(message)).to eq(false)
  end

  it "rejects message with malformed signature" do
    message["Signature"] = "foo=bar,baz=bla,yadda=yadda"
    expect(verifier.valid?(message)).to eq(false)
  end

  context "for asymmetric algorithm" do
    def rsa_public_key
      <<~END
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3JxCbnsXUC+R3NEV/2ke
        gBTL/IjS+RhLQNn18TkVhQTuVeaZkp2jgk6qCGeWIAUTLtNA/pKYhF3bOV2PW2NC
        3QLWvCLEuRgp5wI3FuImpexhTo2u89gixH9GUgIHTIAJ7J8LZ8I8h6MSGi22I0xz
        sWuGHU/hycsy2ofvAkIFwvSw4C0QvFh4fTR8r/knjQ2IMySO9oujUJIdRtNySZ2c
        sbuOgOdXnXMeDis+8qfvRFnBO01/HEK7Sev642FiCZ9XAYerKpclMrlOqUgXSEZQ
        skd/LZxuXixNtiFzBegrW7urj/rte+GAfr+AAQ6EjD/pjqqj6xzytfP6mloWITqo
        4wIDAQAB
        -----END PUBLIC KEY-----
      END
    end

    subject(:verifier) { HttpSignatures::Verifier.new(key_store: key_store) }
    let(:key_store) { HttpSignatures::KeyStore.new("pda" => rsa_public_key) }
    let(:message) { Net::HTTP::Get.new("/path?query=123", headers) }
    let(:headers) { {"Date" => DATE, "Signature" => signature_header} }

    let(:signature_header) do
      'keyId="%s",algorithm="%s",headers="%s",signature="%s"' % [
        "pda",
        "rsa-sha256",
        "(request-target) date",
        "ILBfD6+X+4l7I+LEDhTjar+gsRu3y2DaGwp3MQSHxrCTjGx7HhXJkd+qDShIxAUaCHR1vf6C4UxYRj8KdBEm8/jPZvy380qAk1UCNtNNjhm1eEh7G1xEwVX6IULISWcRqp0ZbzBslTxZOo00WY5eZlDYv0FPiq6XzoRgCRsQTVBVdvbf38DzpLO/VhjdmcyHfLp2MSTlrqz3NQqN0lXEOErWQ1py/ajQiAEN/yDQSmWEnTUYioryP2QuE4WNWMljELnxMJ+YyjrC8ncQ51FoojhiO563dTI0EJxf2zxDz4I8hkKHfv1binNccDsjA1lSI8IPBGfJqEOscO9o668t3Q=="
      ]
    end

    it "verifies a valid message" do
      expect(verifier.valid?(message)).to eq(true)
    end
  end
end
