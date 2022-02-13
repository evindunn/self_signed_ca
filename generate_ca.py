#!/usr/bin/env python3

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from datetime import datetime
from datetime import timedelta
from argparse import ArgumentParser
from os.path import exists as path_exists


def main():
    argparser = ArgumentParser(description="Generate a self-signed CA")
    argparser.add_argument("common_name", help="The CA's common name")
    argparser.add_argument("country", help="The CA's 2-letter country code")
    argparser.add_argument("province", help="The CA's spelled-out state/province")
    argparser.add_argument("locality", help="The CA's locality")
    argparser.add_argument("organization", help="The name of the CA's organization")
    argparser.add_argument("email", help="The contact email for the CA")
    argparser.add_argument("output_file", help="The output file for the certificate")
    argparser.add_argument("-k", "--private-key", help="The private key used to sign the certificate", default=None)
    args = argparser.parse_args()

    if args.private_key is not None:
        keyfile = args.private_key
        if not path_exists(keyfile):
            print("Private key {} does not exist".format(keyfile))
            exit(1)
   
        try:
            with open(args.private_key, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
        except Exception as e:
            print("Invalid key file {}: {}".format(keyfile, e))
            exit(1)

        print("Private key loaded from {}".format(keyfile))

    else:
        keyfile = "ca.key"
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(keyfile, "wb") as f:
            file_content = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            f.write(file_content)
            print("Private key written to {}".format(keyfile))

    now = datetime.today()
    one_year_from_now = now + timedelta(days=365)

    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, args.country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, args.province),
        x509.NameAttribute(NameOID.LOCALITY_NAME, args.locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, args.organization),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, args.email),
        x509.NameAttribute(NameOID.COMMON_NAME, args.common_name),
    ])

    # Self-signed
    builder = builder.subject_name(ca_name).issuer_name(ca_name)

    # Dates
    builder = builder.not_valid_before(datetime.today() - timedelta(minutes=1))
    builder = builder.not_valid_after(one_year_from_now)

    # Extensions
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    builder = builder.add_extension(
        x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH, x509.OID_SERVER_AUTH]),
        critical=False
    )

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), 
        critical=True
    )

    # Misc
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)

    cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256())

    with open(args.output_file, "wb") as f:
        file_content = cert.public_bytes(encoding=serialization.Encoding.PEM)
        f.write(file_content)

    print("Certificate written to {}".format(args.output_file))


if __name__ == "__main__":
    main()
