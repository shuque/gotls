# gotls

gotls connects to a TLS server, performs DANE/PKIX authentication of
the server certificate chain, and then prints out information about
the TLS connection and the certificate.

Usage:

```
gotls, version 0.1.0
Usage: gotls [Options] <host> [<port>]

        If unspecified, the default port 443 is used.

        Options:
        -h          Print this help string
        -m mode     Mode: "dane" or "pkix"
	-s starttls STARTTLS application: smtp/imap/pop
        -4          Use IPv4 transport only
        -6          Use IPv6 transport only
        -r ip       DNS Resolver IP address
        -t N        Query timeout value in seconds (default 3)
```

An example run:

```
$ gotls www.huque.com

DNS TLSA RRset:
  qname: _443._tcp.www.huque.com.
  3 1 1 55f6db74c524acca28b52c0bcfc28eec4596f90d00c2056010ae79901b2eb049
  3 1 1 736a6032543cf64de9d4cfbd5bdffd329027fe1fe860b2396954a9d9db630fd1

## Checking www.huque.com. 2600:3c03:e000:81::a port 443
## Peer Certificate Chain:
   0 CN=www.huque.com
     CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
   1 CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
     CN=DST Root CA X3,O=Digital Signature Trust Co.
## PKIX Verified Chain 0:
   0 CN=www.huque.com
     CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
   1 CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
     CN=DST Root CA X3,O=Digital Signature Trust Co.
   2 CN=DST Root CA X3,O=Digital Signature Trust Co.
     CN=DST Root CA X3,O=Digital Signature Trust Co.
## DANE TLS authentication result:
   WARN: DANE TLSA 3 1 1 [55f6db74..] did not match certificate.
   OK:   DANE TLSA 3 1 1 [736a6032..] matched EE certificate.
## TLS Connection Info:
   TLS version: TLS1.2
   CipherSuite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
## Certificate Info:
   X509 version: 3
   Serial#: 3e041f5c8966fedc98553ae09e071b1c615
   Subject: CN=www.huque.com
   Issuer:  CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
   SAN dNSName: www.huque.com
   Signature Algorithm: SHA256-RSA
   PublicKey Algorithm: RSA
   Inception:  2020-05-03 10:17:09 +0000 UTC
   Expiration: 2020-08-01 10:17:09 +0000 UTC
   KU: DigitalSignature KeyEncipherment
   EKU: ServerAuth ClientAuth
   Is CA?: false
   SKI: eb15c2265f29315b65468412e6a4a2d154f1e5e4
   AKI: a84a6a63047dddbae6d139b7a64565eff3a8eca1
   OSCP Servers: [http://ocsp.int-x3.letsencrypt.org]
   CA Issuer URL: [http://cert.int-x3.letsencrypt.org/]
   CRL Distribution: []
   Policy OIDs: [2.23.140.1.2.1 1.3.6.1.4.1.44947.1.1.1]

## Checking www.huque.com. 50.116.63.23 port 443
## Peer Certificate Chain:
   0 CN=www.huque.com
     CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
   1 CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
     CN=DST Root CA X3,O=Digital Signature Trust Co.
## PKIX Verified Chain 0:
   0 CN=www.huque.com
     CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
   1 CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
     CN=DST Root CA X3,O=Digital Signature Trust Co.
   2 CN=DST Root CA X3,O=Digital Signature Trust Co.
     CN=DST Root CA X3,O=Digital Signature Trust Co.
## DANE TLS authentication result:
   WARN: DANE TLSA 3 1 1 [55f6db74..] did not match certificate.
   OK:   DANE TLSA 3 1 1 [736a6032..] matched EE certificate.
## TLS Connection Info:
   TLS version: TLS1.2
   CipherSuite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
## Certificate Info:
   X509 version: 3
   Serial#: 3e041f5c8966fedc98553ae09e071b1c615
   Subject: CN=www.huque.com
   Issuer:  CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
   SAN dNSName: www.huque.com
   Signature Algorithm: SHA256-RSA
   PublicKey Algorithm: RSA
   Inception:  2020-05-03 10:17:09 +0000 UTC
   Expiration: 2020-08-01 10:17:09 +0000 UTC
   KU: DigitalSignature KeyEncipherment
   EKU: ServerAuth ClientAuth
   Is CA?: false
   SKI: eb15c2265f29315b65468412e6a4a2d154f1e5e4
   AKI: a84a6a63047dddbae6d139b7a64565eff3a8eca1
   OSCP Servers: [http://ocsp.int-x3.letsencrypt.org]
   CA Issuer URL: [http://cert.int-x3.letsencrypt.org/]
   CRL Distribution: []
   Policy OIDs: [2.23.140.1.2.1 1.3.6.1.4.1.44947.1.1.1]

[0] Authentication succeeded for all (2) peers.
```
