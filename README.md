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
gotls, version 0.3.1
Usage: gotls [Options] <host> [<port>]

        If port is omitted, the default port 443 is used. If hostname is an
        IP address string, then a name must be specified via the SNI option.

        Options:
        -h               Print this help string
        -d               Debug mode - print additional info
        -m mode          Mode: "dane" or "pkix"
        -sni name        Specify SNI name to send and verify
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

Host: www.huque.com Port: 443
SNI: www.huque.com
DNS TLSA RRset:
  qname: _443._tcp.www.huque.com.
  3 1 1 6c85cc093c31221cbff9e61cff5e9ca14bfeb0f9bbc341a7695290275d813cf4
  3 1 1 de4369cf0866a1e7626d73db36dbfc4b74097c3c70489a2d3351b6e75e99583a
IP Addresses found:
  2600:3c03:e000:81::a
  50.116.63.23

## Checking www.huque.com 2600:3c03:e000:81::a port 443
DANE TLSA 3 1 1 [6c85cc09..]: OK matched EE certificate
DANE TLSA 3 1 1 [de4369cf..]: FAIL did not match EE certificate
## Peer Certificate Chain:
   0 CN=www.huque.com
     CN=R3,O=Let's Encrypt,C=US
   1 CN=R3,O=Let's Encrypt,C=US
     CN=ISRG Root X1,O=Internet Security Research Group,C=US
   2 CN=ISRG Root X1,O=Internet Security Research Group,C=US
     CN=DST Root CA X3,O=Digital Signature Trust Co.
## PKIX Certificate Chain 0:
   0 CN=www.huque.com
     CN=R3,O=Let's Encrypt,C=US
   1 CN=R3,O=Let's Encrypt,C=US
     CN=ISRG Root X1,O=Internet Security Research Group,C=US
   2 CN=ISRG Root X1,O=Internet Security Research Group,C=US
     CN=ISRG Root X1,O=Internet Security Research Group,C=US
## DANE Certificate Chain 0:
   0 CN=www.huque.com
     CN=R3,O=Let's Encrypt,C=US
   1 CN=R3,O=Let's Encrypt,C=US
     CN=ISRG Root X1,O=Internet Security Research Group,C=US
   2 CN=ISRG Root X1,O=Internet Security Research Group,C=US
     CN=DST Root CA X3,O=Digital Signature Trust Co.
## TLS Connection Info:
   TLS version: TLS1.3
   CipherSuite: TLS_AES_128_GCM_SHA256
## End-Entity Certificate Info:
   X509 version: 3
   Serial#: 32b409bacd77855987674821c95f997dc2b
   Subject: CN=www.huque.com
   Issuer:  CN=R3,O=Let's Encrypt,C=US
   SAN dNSName: www.huque.com
   Signature Algorithm: SHA256-RSA
   PublicKey Algorithm: RSA 2048-Bits
   Inception:  2022-02-18 18:09:53 +0000 UTC
   Expiration: 2022-05-19 18:09:52 +0000 UTC
   KU: DigitalSignature KeyEncipherment
   EKU: ServerAuth ClientAuth
   Is CA?: false
   SKI: e2fc45cf4127bb62abead6bf3c74a31bc068f1c2
   AKI: 142eb317b75856cbae500940e61faf9d8b14c2c6
   OSCP Servers: [http://r3.o.lencr.org]
   CA Issuer URL: [http://r3.i.lencr.org/]
   CRL Distribution: []
   Policy OIDs: [2.23.140.1.2.1 1.3.6.1.4.1.44947.1.1.1]
Result: DANE OK

## Checking www.huque.com 50.116.63.23 port 443
DANE TLSA 3 1 1 [6c85cc09..]: OK matched EE certificate
DANE TLSA 3 1 1 [de4369cf..]: FAIL did not match EE certificate
## Peer Certificate Chain:
   0 CN=www.huque.com
     CN=R3,O=Let's Encrypt,C=US
   1 CN=R3,O=Let's Encrypt,C=US
     CN=ISRG Root X1,O=Internet Security Research Group,C=US
   2 CN=ISRG Root X1,O=Internet Security Research Group,C=US
     CN=DST Root CA X3,O=Digital Signature Trust Co.
## PKIX Certificate Chain 0:
   0 CN=www.huque.com
     CN=R3,O=Let's Encrypt,C=US
   1 CN=R3,O=Let's Encrypt,C=US
     CN=ISRG Root X1,O=Internet Security Research Group,C=US
   2 CN=ISRG Root X1,O=Internet Security Research Group,C=US
     CN=ISRG Root X1,O=Internet Security Research Group,C=US
## DANE Certificate Chain 0:
   0 CN=www.huque.com
     CN=R3,O=Let's Encrypt,C=US
   1 CN=R3,O=Let's Encrypt,C=US
     CN=ISRG Root X1,O=Internet Security Research Group,C=US
   2 CN=ISRG Root X1,O=Internet Security Research Group,C=US
     CN=DST Root CA X3,O=Digital Signature Trust Co.
## TLS Connection Info:
   TLS version: TLS1.3
   CipherSuite: TLS_AES_128_GCM_SHA256
## End-Entity Certificate Info:
   X509 version: 3
   Serial#: 32b409bacd77855987674821c95f997dc2b
   Subject: CN=www.huque.com
   Issuer:  CN=R3,O=Let's Encrypt,C=US
   SAN dNSName: www.huque.com
   Signature Algorithm: SHA256-RSA
   PublicKey Algorithm: RSA 2048-Bits
   Inception:  2022-02-18 18:09:53 +0000 UTC
   Expiration: 2022-05-19 18:09:52 +0000 UTC
   KU: KeyEncipherment DigitalSignature
   EKU: ServerAuth ClientAuth
   Is CA?: false
   SKI: e2fc45cf4127bb62abead6bf3c74a31bc068f1c2
   AKI: 142eb317b75856cbae500940e61faf9d8b14c2c6
   OSCP Servers: [http://r3.o.lencr.org]
   CA Issuer URL: [http://r3.i.lencr.org/]
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

Host: mta.openssl.org Port: 25
SNI: mta.openssl.org
STARTTLS application: smtp
DNS TLSA RRset:
  qname: _25._tcp.mta.openssl.org.
  3 1 1 6cf12d78fbf242909d01b96ab5590812954058dc32f8415f048fff064291921e
IP Addresses found:
  2001:608:c00:180::1:e6

## Checking mta.openssl.org 2001:608:c00:180::1:e6 port 25
DANE TLSA 3 1 1 [6cf12d78..]: OK matched EE certificate
## STARTTLS Transcript:
recv: 220-mta.openssl.org ESMTP Postfix
recv: 220 mta.openssl.org ESMTP Postfix
send: EHLO cheetara.huque.com
recv: 250-mta.openssl.org
recv: 250-PIPELINING
recv: 250-SIZE 36700160
recv: 250-VRFY
recv: 250-ETRN
recv: 250-STARTTLS
recv: 250-ENHANCEDSTATUSCODES
recv: 250-8BITMIME
recv: 250-DSN
recv: 250 CHUNKING
send: STARTTLS
recv: 220 2.0.0 Ready to start TLS
## Peer Certificate Chain:
   0 CN=mta.openssl.org
     CN=R3,O=Let's Encrypt,C=US
   1 CN=R3,O=Let's Encrypt,C=US
     CN=ISRG Root X1,O=Internet Security Research Group,C=US
   2 CN=ISRG Root X1,O=Internet Security Research Group,C=US
     CN=DST Root CA X3,O=Digital Signature Trust Co.
## PKIX Certificate Chain 0:
   0 CN=mta.openssl.org
     CN=R3,O=Let's Encrypt,C=US
   1 CN=R3,O=Let's Encrypt,C=US
     CN=ISRG Root X1,O=Internet Security Research Group,C=US
   2 CN=ISRG Root X1,O=Internet Security Research Group,C=US
     CN=ISRG Root X1,O=Internet Security Research Group,C=US
## DANE Certificate Chain 0:
   0 CN=mta.openssl.org
     CN=R3,O=Let's Encrypt,C=US
   1 CN=R3,O=Let's Encrypt,C=US
     CN=ISRG Root X1,O=Internet Security Research Group,C=US
   2 CN=ISRG Root X1,O=Internet Security Research Group,C=US
     CN=DST Root CA X3,O=Digital Signature Trust Co.
## TLS Connection Info:
   TLS version: TLS1.3
   CipherSuite: TLS_AES_128_GCM_SHA256
## End-Entity Certificate Info:
   X509 version: 3
   Serial#: 368362cd51ed35691bafe9deb7d0e0b46cf
   Subject: CN=mta.openssl.org
   Issuer:  CN=R3,O=Let's Encrypt,C=US
   SAN dNSName: mta.openssl.org
   Signature Algorithm: SHA256-RSA
   PublicKey Algorithm: RSA 4096-Bits
   Inception:  2022-02-02 11:00:05 +0000 UTC
   Expiration: 2022-05-03 11:00:04 +0000 UTC
   KU: DigitalSignature KeyEncipherment
   EKU: ServerAuth ClientAuth
   Is CA?: false
   SKI: e27f74ac4c9b0c6694d6af580f005d7f34e0e80c
   AKI: 142eb317b75856cbae500940e61faf9d8b14c2c6
   OSCP Servers: [http://r3.o.lencr.org]
   CA Issuer URL: [http://r3.i.lencr.org/]
   CRL Distribution: []
   Policy OIDs: [2.23.140.1.2.1 1.3.6.1.4.1.44947.1.1.1]
Result: DANE OK

[0] Authentication succeeded for all (1) peers.
```
