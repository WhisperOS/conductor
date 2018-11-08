# Conductor

## 

This example code demonstrates how to use the OpenSSL C API to perform
the actions by a Certificate Authority.

### How it works:

  - We generate a self-signed CA
  - We generate a Intermediate CA and sign it with the First CA
  - We generate a server cert and sign it with the intermediate.

### During each step we:

  - Generate a private RSA key.
  - Generate a certificate request.
  - Sign this certificate request using the CA certificate or ourselves.

All certs are saved to file, and are named accordingly.

## How to use

1. Run `make` which will compile the application.
2. Run `./conductor` which will generate a certificate an intermediate and a Root CA
3. Run `./conductor server hostname.domain.tld` will generate a server cert.
4. Run `./condictor user   name@domain.tld` will generate a user cert.
5. Run `./conductor server hostname.domain.tld -d sub.domain.tld -i ipaddress` will add SAN items

## For reference only

## How to Manually verify that a certificate is signed by a CA

If you want to check that the generated certificate is indeed
signed by the CA. You must first place the certificate output of `./cert` into
`cert.crt`.

```
$ openssl verify -CAfile ca.pem cert.crt
cert.crt: OK
```

If an error occurs, expect some other output such as `self signed certificate` etc.

## How to manually verify the certificate with the CA key

This is what we'll do with C code instead.

```
$ openssl x509 -req -days 365 -in vnf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out vnf.crt
```
