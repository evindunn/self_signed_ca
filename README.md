# Usage
```
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip install -r requirements.txt
```

```
$ ./generate_ca.py -h
usage: generate_ca.py [-h] [-k PRIVATE_KEY] [-d EXPIRY_DAYS] common_name country province locality organization email

Generate a self-signed CA

positional arguments:
  common_name           The CA's common name
  country               The CA's 2-letter country code
  province              The CA's spelled-out state/province
  locality              The CA's locality
  organization          The name of the CA's organization
  email                 The contact email for the CA

options:
  -h, --help            show this help message and exit
  -k PRIVATE_KEY, --private-key PRIVATE_KEY
                        The private key used to sign the certificate
  -d EXPIRY_DAYS, --expiry-days EXPIRY_DAYS
                        Days until ca expires
```

```
$ ./generate_ca.py localdomain.net US Arizona Flagstaff evindunn.com certmanager@evindunn.com ca.crt
Private key written to ca.key
Certificate written to ca.crt

$ openssl x509 -text -noout -in ca.crt 
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            1f:50:c3:4f:3a:bd:17:dc:5f:58:98:b8:79:42:c4:d1:ed:e1:65:7d
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, ST = Arizona, L = Flagstaff, O = evindunn.com, emailAddress = certmanager@evindunn.com, CN = localdomain.net
        Validity
            Not Before: Feb 13 12:09:47 2022 GMT
            Not After : Feb 13 12:10:47 2023 GMT
        Subject: C = US, ST = Arizona, L = Flagstaff, O = evindunn.com, emailAddress = certmanager@evindunn.com, CN = localdomain.net
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption

...

```

```
$ ./generate_cert.py -h
usage: generate_cert.py [-h] [-a ALTERNATIVE_NAMES [ALTERNATIVE_NAMES ...]] [-k PRIVATE_KEY] ca_key ca_cert common_name

Generate a self-signed CA

positional arguments:
  ca_key                The path to the private key for the signing CA
  ca_cert               The path to the certificate for the signing CA
  common_name           The certificate's common name

optional arguments:
  -h, --help            show this help message and exit
  -a ALTERNATIVE_NAMES [ALTERNATIVE_NAMES ...], --alternative-name ALTERNATIVE_NAMES [ALTERNATIVE_NAMES ...]
                        Alternative names for the certificate
  -k PRIVATE_KEY, --private-key PRIVATE_KEY
                        The private key used to sign the certificate
```

```
$ ./generate_cert.py ca.key ca.crt test.com -k test.com.key
Private key loaded from test.com.key
Certificate written to test.com.crt

$ openssl x509 -text -noout -in test.com.crt 
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            6a:69:c6:db:ea:77:97:0c:5a:11:43:b8:13:4d:67:87:e9:1f:44:c9
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, ST = Arizona, L = Flagstaff, O = evindunn.com, emailAddress = certmanager@evindunn.com, CN = localdomain.net
        Validity
            Not Before: Feb 13 12:12:10 2022 GMT
            Not After : Feb 13 12:13:10 2023 GMT
        Subject: C = US, ST = Arizona, L = Flagstaff, O = evindunn.com, emailAddress = certmanager@evindunn.com, CN = test.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption

...

```
