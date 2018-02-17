require 'net/http'

RSpec.describe "IETF Draft v9 examples" do

  def public_key
    <<~END
    -----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
    6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
    Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
    oYi+1hqp1fIekaxsyQIDAQAB
    -----END PUBLIC KEY-----
    END
  end

  def private_key
    <<~END
    -----BEGIN RSA PRIVATE KEY-----
    MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
    NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
    UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
    AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
    QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
    kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
    f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
    412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
    mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
    kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
    gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
    G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
    7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
    -----END RSA PRIVATE KEY-----
    END
  end


  def example_message
    req = Net::HTTP::Post.new(
      "/foo?param=value&pet=dog",
      "Host" => "example.com",
      "Date" => "Sun, 05 Jan 2014 21:31:40 GMT",
      "Content-Type" => "application/json",
      "Digest" => "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
      "Content-Length" => "18",
    )
    req.body = '{"hello": "world"}'
    req
  end

  it "outputs the same signature header as the specification provides rsa-sha256" do
    ctx = HttpSignatures::Context.new(
      algorithm: "rsa-sha256",
      keys: {"Test" => private_key},
      signing_key_id: "Test",
      headers: ["(request-target)", "Host", "Date"],
    )
    signed_message = ctx.signer.sign(example_message)
    expect(signed_message["Signature"]).to eq(%q[keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date",signature="qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0="])
  end
end

