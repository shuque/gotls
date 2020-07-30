# gotls

gotls is a TLS server diagnostic tool that understands DANE and PKIX
authentication. It connects to a TLS server, performs DANE and/or PKIX
authentication of the server certificate chain, and then optionally
prints out information about the TLS connection and the certificate.


### Pre-requisites

* Go
* Go dane package: https://github.com/shuque/dane
* Go dns package: https://github.com/miekg/dns


DANE authentication requires the use of a validating DNS resolver,
that sets the AD bit on authenticated responses. By default, this
program uses the resolvers listed in /etc/resolv.conf, but
an alternate resolver address and port can be specified with the
-r and -rp command line options. If no secure DANE TLSA records
are found, or if the resolver doesn't validate, the program will
fallback to normal PKIX authentication. The "-m dane" switch can
be used to prevent this fallback and force DANE authentication.

STARTLS is supported for SMTP, POP3, IMAP, and XMPP via the
"-s appname" option. If the STARTTLS application service expects
a service name different than the server hostname, this can be
specified with the "-n name" option. Per current spec, this
program does not perform certificate hostname checks for DANE-EE
mode TLSA records, but this can overridden with the "-dane-ee-name"
option. For SMTP STARTTLS the program ignores PKIX-* mode TLSA
records, unless the "-smtp-any-mode" option is specified.

There are several other command line options, which are listed in
the Usage section below.


### Limitations

gotls does not do certificate revocation checks (CRL, OCSP, or
stapled OCSP responses). A future version might support checking
stapled OCSP responses.


### Building

Just run 'go build'. This will generate the executable 'gotls'.

### Usage:

```
gotls, version 0.2.7
Usage: gotls [Options] <host> [<port>]

        If unspecified, the default port 443 is used.

        Options:
        -h               Print this help string
        -d               Debug mode - print additional info
        -m mode          Mode: "dane" or "pkix"
        -s starttls      STARTTLS application (smtp, imap, pop3)
        -n name          Service name (if different from hostname)
        -4               Use IPv4 transport only
        -6               Use IPv6 transport only
        -r ip            DNS Resolver IP address
        -rp port         DNS Resolver port (default 53)
        -t N             Query timeout value in seconds (default 3)
        -dane-ee-name    Do hostname check even for DANE-EE mode
        -smtp-any-mode   Allow STARTTLS SMTP for any DANE usage mode
        -noverify        Don't perform server certificate verification
        -printchain      Print details of full certificate chain
```

### Exit codes:

The program exits with the following codes:

* 0 - Authentication succeeded for all peers.
* 1 - Authentication succeeded for some but not all peers
* 2 - Authentication failed for all peers
* 3 - Some other error (incorrect command line arguments, etc)
* 4 - Server authentication was not performed. (-noverify option)


### Example runs:

Check the HTTPS (port 443) TLS service at www.huque.com.

```
$ gotls www.huque.com

## Checking www.huque.com. 2600:3c03:e000:81::a port 443
Result: DANE OK

## Checking www.huque.com. 50.116.63.23 port 443
Result: DANE OK

[0] Authentication succeeded for all (2) peers.
```

Check the HTTPS service at amazon.com. Here, no DANE TLSA records
are found (in fact the zone is unsigned, so we get an unauthenticated
response for the TLSA query, thus negating the possibility of DANE).
So, the program prints a warning and falls back to traditional PKIX
authentication:

```
$ gotls www.amazon.com

No DANE TLSA records found.

## Checking www.amazon.com. 99.84.117.249 port 443
Result: PKIX OK

[0] Authentication succeeded for all (1) peers.
```

Forcing DANE authentication for the previous service with the
"-m dane" switch produces an authentication failure result:

```
$ gotls -m dane www.amazon.com

No DANE TLSA records found.
```

Using the -d (debug) switch displays a great deal of additional
diagnostic information, including the actual DANE TLSA records,
offered and verified certificate chains, DANE record processing
results, and verbose details of the server certificate. (Verbose
details of the entire certificate chain can be obtained via the
-printchain option):


```
$ gotls -d www.huque.com

Host: www.huque.com. Port: 443
DNS TLSA RRset:
  qname: _443._tcp.www.huque.com.
  3 1 1 736a6032543cf64de9d4cfbd5bdffd329027fe1fe860b2396954a9d9db630fd1
  3 1 1 55f6db74c524acca28b52c0bcfc28eec4596f90d00c2056010ae79901b2eb049
IP Addresses found:
  2600:3c03:e000:81::a
  50.116.63.23

## Checking www.huque.com. 2600:3c03:e000:81::a port 443
DANE TLSA 3 1 1 [736a6032..]: OK matched EE certificate
DANE TLSA 3 1 1 [55f6db74..]: FAIL did not match EE certificate
## Peer Certificate Chain:
   0 CN=www.huque.com
     CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
   1 CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
     CN=DST Root CA X3,O=Digital Signature Trust Co.
## Verified Certificate Chain 0:
   0 CN=www.huque.com
     CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
   1 CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
     CN=DST Root CA X3,O=Digital Signature Trust Co.
   2 CN=DST Root CA X3,O=Digital Signature Trust Co.
     CN=DST Root CA X3,O=Digital Signature Trust Co.
## TLS Connection Info:
   TLS version: TLS1.2
   CipherSuite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
## End-Entity Certificate Info:
   X509 version: 3
   Serial#: 3e041f5c8966fedc98553ae09e071b1c615
   Subject: CN=www.huque.com
   Issuer:  CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
   SAN dNSName: www.huque.com
   Signature Algorithm: SHA256-RSA
   PublicKey Algorithm: RSA 2048-Bits
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
Result: DANE OK

## Checking www.huque.com. 50.116.63.23 port 443
DANE TLSA 3 1 1 [736a6032..]: OK matched EE certificate
DANE TLSA 3 1 1 [55f6db74..]: FAIL did not match EE certificate
## Peer Certificate Chain:
   0 CN=www.huque.com
     CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
   1 CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
     CN=DST Root CA X3,O=Digital Signature Trust Co.
## Verified Certificate Chain 0:
   0 CN=www.huque.com
     CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
   1 CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
     CN=DST Root CA X3,O=Digital Signature Trust Co.
   2 CN=DST Root CA X3,O=Digital Signature Trust Co.
     CN=DST Root CA X3,O=Digital Signature Trust Co.
## TLS Connection Info:
   TLS version: TLS1.2
   CipherSuite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
## End-Entity Certificate Info:
   X509 version: 3
   Serial#: 3e041f5c8966fedc98553ae09e071b1c615
   Subject: CN=www.huque.com
   Issuer:  CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
   SAN dNSName: www.huque.com
   Signature Algorithm: SHA256-RSA
   PublicKey Algorithm: RSA 2048-Bits
   Inception:  2020-05-03 10:17:09 +0000 UTC
   Expiration: 2020-08-01 10:17:09 +0000 UTC
   KU: KeyEncipherment DigitalSignature
   EKU: ServerAuth ClientAuth
   Is CA?: false
   SKI: eb15c2265f29315b65468412e6a4a2d154f1e5e4
   AKI: a84a6a63047dddbae6d139b7a64565eff3a8eca1
   OSCP Servers: [http://ocsp.int-x3.letsencrypt.org]
   CA Issuer URL: [http://cert.int-x3.letsencrypt.org/]
   CRL Distribution: []
   Policy OIDs: [2.23.140.1.2.1 1.3.6.1.4.1.44947.1.1.1]
Result: DANE OK

[0] Authentication succeeded for all (2) peers.
```

The program understands a number of application services that use
STARTTLS negotiation: SMTP, POP3, IMAP, XMPP-CLIENT and XMPP-SERVER.
Using the "-s appname" option will use this mode.

Below, we check only the IPv6 (-6) SMTP STARTTLS (-s smtp) service at
mta.openssl.org port 25:

```
$ gotls -d -6 -s smtp mta.openssl.org 25

DNS TLSA RRset:
  qname: _25._tcp.mta.openssl.org.
  3 1 1 6cf12d78fbf242909d01b96ab5590812954058dc32f8415f048fff064291921e

## Checking mta.openssl.org. 2001:608:c00:180::1:e6 port 25
DANE TLSA 3 1 1 [6cf12d78..]: OK matched EE certificate
## STARTTLS Transcript:
recv: 220-mta.openssl.org ESMTP Postfix
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
## TLS Connection Info:
   TLS version: TLS1.2
   CipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
## End-Entity Certificate Info:
   X509 version: 3
   Serial#: 3052db8c7f9b73c1a94b78535ab43bcacef
   Subject: CN=mta.openssl.org
   Issuer:  CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
   SAN dNSName: mta.openssl.org
   Signature Algorithm: SHA256-RSA
   PublicKey Algorithm: RSA 4096-Bits
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
Result: DANE OK

[0] Authentication succeeded for all (1) peers.
```
