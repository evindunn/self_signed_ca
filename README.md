# Installation
```bash
# Create & activate a venv
python3 -m venv venv
source venv/bin/activate

# Install tools
pip install git+https://github.com/evindunn/self_signed_ca.git

# ssca and ssc commands are available within the venv
ssca --help
ssc --help
```

# Usage

## ssca

Generate a self-signed CA

```
usage: ssca [-h] [-k PRIVATE_KEY] [-d EXPIRY_DATE]
            common_name country province locality organization email

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
  -d EXPIRY_DATE, --expiry-date EXPIRY_DATE
                        Expiry date conforming to iso-8601 (2007-04-05T14:30Z)
```

## ssc

Generate a cert given a CA

```
usage: ssc [-h] [-a ALTERNATIVE_NAMES [ALTERNATIVE_NAMES ...]]
           [-k PRIVATE_KEY] [-d EXPIRY_DAYS]
           ca_key ca_cert common_name

Generate a self-signed CA

positional arguments:
  ca_key                The path to the private key for the signing CA
  ca_cert               The path to the certificate for the signing CA
  common_name           The certificate's common name

options:
  -h, --help            show this help message and exit
  -a ALTERNATIVE_NAMES [ALTERNATIVE_NAMES ...], --alternative-names ALTERNATIVE_NAMES [ALTERNATIVE_NAMES ...]
                        Alternative names for the certificate
  -k PRIVATE_KEY, --private-key PRIVATE_KEY
                        The private key used to sign the certificate
  -d EXPIRY_DAYS, --expiry-date EXPIRY_DAYS
                        Days until ca expires
```
