# CA signing using OpenSSL C API

This example code demonstrates how to use the OpenSSL C API to perform
the actions by a CA. In short, it does the following:

How it works:

  - We generate a self-signed CA
  - We generate a Intermediate CA and sign it with the First CA
  - We generate a server cert and sign it with the intermediate.

During each step we:

  - Generate a private RSA key.
  - Generate a certificate request.
  - Sign this certificate request using the CA certificate or ourselves.

All certs are saved to file, and are named accordingly.

## How-to

1. Run `make` which will compile the application.
2. Run `./conductor` which will generate a certificate an intermediate and a Root CA
3. Run `./conductor server hostname.domain.tld` will generate a server cert.
4. Run `./condictor user   name@domain.tld` will generate a user cert.
5. Run `./conductor server hostname.domain.tld -d sub.domain.tld -i ipaddress` will add SAN items

## Manually verifying that a certificate is signed by a CA

For reference only; if you want to check that the generated certificate is indeed
signed by the CA. You must first place the certificate output of `./cert` into
`cert.crt`.

```
$ openssl verify -CAfile ca.pem cert.crt
cert.crt: OK
```

If an error occurs, expect some other output such as `self signed certificate` etc.

## Manually signing the certificate with the CA key

For reference only; this is what we'll do with C code instead.

```
$ openssl x509 -req -days 365 -in vnf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out vnf.crt
```
