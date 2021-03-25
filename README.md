# Demo how to use create and verify a JWT

## Prerequisites

- Create private and public keys (RS256)

```shell script
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

Convert public key from PEM to DER format

```shell script
openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem -out private.der -nocrypt
```