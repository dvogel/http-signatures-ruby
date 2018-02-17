#!/usr/bin/env bash
set -o errexit
set -o xtrace

# Assumes openssl 1.1.0g or compatible
openssl genrsa -out spec/example.key
openssl dgst -sign spec/example.key -out spec/example.sig spec/example.msg
base64 -w0 < spec/example.sig > spec/example.sig.base64

