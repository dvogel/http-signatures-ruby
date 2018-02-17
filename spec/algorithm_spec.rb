require "base64"

RSpec.describe HttpSignatures::Algorithm do

  def self.symmetric_key
    "the-key"
  end

  def input
    "the string\nto sign"
  end

  def self.rsa_key
    <<~END
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEA3JxCbnsXUC+R3NEV/2kegBTL/IjS+RhLQNn18TkVhQTuVeaZ
    kp2jgk6qCGeWIAUTLtNA/pKYhF3bOV2PW2NC3QLWvCLEuRgp5wI3FuImpexhTo2u
    89gixH9GUgIHTIAJ7J8LZ8I8h6MSGi22I0xzsWuGHU/hycsy2ofvAkIFwvSw4C0Q
    vFh4fTR8r/knjQ2IMySO9oujUJIdRtNySZ2csbuOgOdXnXMeDis+8qfvRFnBO01/
    HEK7Sev642FiCZ9XAYerKpclMrlOqUgXSEZQskd/LZxuXixNtiFzBegrW7urj/rt
    e+GAfr+AAQ6EjD/pjqqj6xzytfP6mloWITqo4wIDAQABAoIBAQDQrxfAPrv85CLM
    iRSP+LYbXpDfn+ZCL5LwE74so10R6Woy4+Id6PSFDTiWnrZKL8LHpppyteWEQOxh
    RXmYbzsOqeLLMPB6TrtEhLnr8Z2xkvsxPaFjlO6+hc7VQIn6+Ztps8EsM3bir4Uu
    MlN67JT8HcRN8gSZyJegVLnont+oW+D+0OxVzGDthmboMyQZRve0bKbVhd9qcUqz
    BfYOcyRG8XgpkOR7o6P4vFMbkMiR86UVL79/FBJZZKRaaqG2toGHSObkewZI4hJr
    QvAEPUbQXs1ASoU5vHfAj3H2L0hFFRWldxLsDV85ByKjkYnsohVGiAxw6wJ//Go9
    Apqf1BHxAoGBAPe1NDDpmw7yJs2ityfI4gOBJtisSBAn1u/j+4j2iqP+I1jKqWdz
    FHCayvR+74ZVz3VToQ+5xGPKScnfd7O2NtFwf9+ejMqd4f+Y1QqrpZvcAbjNhJ7C
    HXbCeJiahrzOiWOzPQBiOA4UHv4lV9o7j6g/vUV30XEHKKBGSwzS1YfHAoGBAOP+
    1k5jz+i9A5svze+gci1YAl+FkWTsuCZbRG2t6qpMv3wBzmKuQ2zGIxGKaGwXhy/Y
    n1vGWE/k9RyLoonft5uNb6IQuCzLbkAvPbmKEJOc8OzGSgTDOQct54cOVuAI+6D5
    H+hhOUcuAWSzmXjo8umrxJUpTlmbTtMkMfTSjO4FAoGBAM3c+K0V2FoJgZow+srD
    tqJ2+ZPlSlay5XylGmzviLVWBoZKl5N0Hq6e1sFvpR0dv7agdCCfoMnWWpC9ebwP
    WWuidYOhPx09LY/Asn2VvaLUq1Gs6+UNKnOCl7sr4YKUm7YSRkZFWpTIwCEzY9no
    2jFYF7LeK2AmNOtOwBy+M9wNAoGAFfj9VliwNNHigxY8Vpez6ULOF76boIpfxPKO
    ybM1Jmx3F9Bkv4Xj4ZvGzW31WlV6JdZOpV2cLTb3mGSsqXTyEP+0fn32AfspCO6E
    mFkB9/fsECWcBJF78YEvCwkKvlSfS4g21wJnrsB0Sew1Ij3xCywOqgFtF52sHxUh
    62JPSrECgYAz3wDhklKYtWOtSAoiQmH/ZOS8JMbfYoKriPOYx/96jAsWFGkHkOja
    2shdA6oYY4dBNUNL0UWfsJ/Qn0wAs1sMRb8YHmA8LH8ES8jGRl4OFrmDZtIszlgY
    aEqD1Urq7ZvBtz7U547P2vyQVvF/IWcBDVRda7teAzyIWCSHAfCgcg==
    -----END RSA PRIVATE KEY-----
    END
  end

  def self.rsa_sha256_sig
    "JdYUAQf8G+j5OUZa6ODid1skbPkZ4NB+NOSGn+TBsJJsn5tXYhESlkrOLO8tJ2he3tqGSzcQ8TMb4jDhyQMcdIs3+DlCJcYFw+0DcTYO68KOI0Mt8+5MTegcr0xGE5psU0WopiWAEcFZ31kq3ZTWhdJQVweca3mY47mXXjUnrP4ks0H9tawcS9jCZ1TlCJRKJzctpkqRvyTtsgCQ4ruNzzCrnsesuy+QEUKwTlwttgX8OCItXZe4mpjPaxQ4e16HFP7sk9o6jg1o7wTIOAStSEZjumuvXBSwiuujL5bA6NNvJPtNhpoghqS6u/wZ8/jSwm7q4REtroj7jVB6Ah7ssQ=="
  end

  context "for shared secret algorithms" do
    [
      ["hmac-sha1", symmetric_key, "bXPeVc5ySIyeUapN7mpMsJRnxVg="],
      ["hmac-sha256", symmetric_key, "hRQ5zpbGudR1hokS4PqeAkveKmz2dd8SCgV8OHcramI="],
      ["rsa-sha256", rsa_key, rsa_sha256_sig],
    ].map do |name, key, base64_signature|
      describe ".create('#{name}')" do
        let(:algorithm) { HttpSignatures::Algorithm.create(name) }
        it "has #name == '#{name}'" do
          expect(algorithm.name).to eq(name)
        end
        it "produces known-good signature" do
          signature = algorithm.sign(key, input)
          expect(signature).to eq(Base64.strict_decode64(base64_signature))
        end
      end

    end
  end

  it "raises error for unknown algorithm" do
    expect {
      HttpSignatures::Algorithm.create(name: "nope", key: nil)
    }.to raise_error(HttpSignatures::Algorithm::UnknownAlgorithm)
  end

end
