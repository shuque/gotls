# gotls

gotls connects to a TLS server, performs DANE/PKIX authentication of
the server certificate chain, and then prints out information about
the TLS connection and the certificate.


### Pre-requisites

* Go
* Miek Gieben's Go dns package: https://github.com/miekg/dns

DANE authentication requires the use of a validating DNS resolver,
that sets the AD bit on authenticated responses. By default, this
program uses the first resolver listed in /etc/resolv.conf. If
the resolver doesn't validate, the program will fallback to normal
PKIX authentication (unless the "-m dane" switch is provided which
forces DANE). The "-r" option can be used to specify an alternative
DNS resolver IP address.

### Limitations

gotls does not do certificate revocation checks (CRL, OCSP, or
stapled OCSP response). A future version might.


### Building

Just run 'go build'. This will generate the executable 'gotls'.

### Usage:

```
gotls, version 0.1.0
Usage: gotls [Options] <host> [<port>]

        If unspecified, the default port 443 is used.

        Options:
        -h          Print this help string
        -m mode     Mode: "dane" or "pkix"
	-s starttls STARTTLS application (smtp, imap, pop3)
	-n name     Service name (if different from hostname)
        -4          Use IPv4 transport only
        -6          Use IPv6 transport only
        -r ip       DNS Resolver IP address
        -t N        Query timeout value in seconds (default 3)
```

### Example runs:

Check the HTTPS (port 443) TLS service at www.huque.com:

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

Check only the IPv6 SMTP STARTTLS service at mta.openssl.org:

```
$ gotls -6 -s smtp mta.openssl.org 25

DNS TLSA RRset:
  qname: _25._tcp.mta.openssl.org.
  3 1 1 6cf12d78fbf242909d01b96ab5590812954058dc32f8415f048fff064291921e

## Checking mta.openssl.org. 2001:608:c00:180::1:e6 port 25
## STARTTLS application: smtp
recv: 220 mta.openssl.org ESMTP Postfix
send: EHLO localhost
recv: 250-mta.openssl.org
recv: 250-PIPELINING
recv: 250-SIZE 36700160
recv: 250-VRFY
recv: 250-ETRN
recv: 250-STARTTLS
recv: 250-ENHANCEDSTATUSCODES
recv: 250-8BITMIME
recv: 250 DSN
send: STARTTLS
recv: 220 2.0.0 Ready to start TLS
## Peer Certificate Chain:
   0 CN=mta.openssl.org
     CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
   1 CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
     CN=DST Root CA X3,O=Digital Signature Trust Co.
## PKIX Verified Chain 0:
   0 CN=mta.openssl.org
     CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
   1 CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
     CN=DST Root CA X3,O=Digital Signature Trust Co.
   2 CN=DST Root CA X3,O=Digital Signature Trust Co.
     CN=DST Root CA X3,O=Digital Signature Trust Co.
## DANE TLS authentication result:
   OK:   DANE TLSA 3 1 1 [6cf12d78..] matched EE certificate.
## TLS Connection Info:
   TLS version: TLS1.2
   CipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
## Certificate Info:
   X509 version: 3
   Serial#: 3052db8c7f9b73c1a94b78535ab43bcacef
   Subject: CN=mta.openssl.org
   Issuer:  CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
   SAN dNSName: mta.openssl.org
   Signature Algorithm: SHA256-RSA
   PublicKey Algorithm: RSA
   Inception:  2020-04-22 23:00:11 +0000 UTC
   Expiration: 2020-07-21 23:00:11 +0000 UTC
   KU: DigitalSignature KeyEncipherment
   EKU: ServerAuth ClientAuth
   Is CA?: false
   SKI: e27f74ac4c9b0c6694d6af580f005d7f34e0e80c
   AKI: a84a6a63047dddbae6d139b7a64565eff3a8eca1
   OSCP Servers: [http://ocsp.int-x3.letsencrypt.org]
   CA Issuer URL: [http://cert.int-x3.letsencrypt.org/]
   CRL Distribution: []
   Policy OIDs: [2.23.140.1.2.1 1.3.6.1.4.1.44947.1.1.1]

[0] Authentication succeeded for all (1) peers.
```
