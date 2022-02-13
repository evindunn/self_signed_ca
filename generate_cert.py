#!/usr/bin/env python3

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID, ObjectIdentifier
from datetime import datetime
from datetime import timedelta
from argparse import ArgumentParser
from os.path import exists as path_exists
from re import fullmatch
from ipaddress import ip_address


REGEXP_IP_ADDR = r"(\d{1,3}\.){3}\d{1,3}"


def load_private_key(file: str):
    with open(file, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key


def get_subject_oid_attribute(cert: x509.Certificate, oid: ObjectIdentifier):
    attrs = cert.subject.get_attributes_for_oid(oid)
    if len(attrs) > 0:
        return attrs[0].value
    return ""


def main():
    argparser = ArgumentParser(description="Generate a self-signed CA")
    argparser.add_argument("ca_key", help="The path to the private key for the signing CA")
    argparser.add_argument("ca_cert", help="The path to the certificate for the signing CA")
    argparser.add_argument("common_name", help="The certificate's common name")
    argparser.add_argument("-a", "--alternative-names", dest="alternative_names", nargs="+", help="Alternative names for the certificate", default=list())
    argparser.add_argument("-k", "--private-key", help="The private key used to sign the certificate", default=None)
    args = argparser.parse_args()

    if args.private_key is not None:
        keyfile = args.private_key
        if not path_exists(keyfile):
            print("Private key {} does not exist".format(keyfile))
            exit(1)
   
        try:
            private_key = load_private_key(args.private_key)
        except Exception as e:
            print("Invalid key file {}: {}".format(keyfile, e))
            exit(1)

        print("Private key loaded from {}".format(keyfile))

    else:
        keyfile = "{}.key".format(args.common_name)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(keyfile, "wb") as f:
            file_content = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            f.write(file_content)
            print("Private key written to {}".format(keyfile))

    if not path_exists(args.ca_key):
        print("CA key {} not found".format(args.ca_key))
        exit(1)

    if not path_exists(args.ca_cert):
        print("CA cert {} not found".format(args.ca_cert))
        exit(1)

    ca_key = load_private_key(args.ca_key)

    with open(args.ca_cert, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    now = datetime.today()
    one_year_from_now = now + timedelta(days=365)

    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()

    country = get_subject_oid_attribute(ca_cert, NameOID.COUNTRY_NAME)
    prov = get_subject_oid_attribute(ca_cert, NameOID.STATE_OR_PROVINCE_NAME)
    locality = get_subject_oid_attribute(ca_cert, NameOID.LOCALITY_NAME)
    org = get_subject_oid_attribute(ca_cert, NameOID.ORGANIZATION_NAME)
    email = get_subject_oid_attribute(ca_cert, NameOID.EMAIL_ADDRESS)
    
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, prov),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        x509.NameAttribute(NameOID.COMMON_NAME, args.common_name),
    ])

    # Self-signed
    builder = builder.subject_name(ca_name).issuer_name(ca_cert.subject)

    # Dates
    builder = builder.not_valid_before(datetime.today() - timedelta(minutes=1))
    builder = builder.not_valid_after(one_year_from_now)

    # Not a CA
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), 
        critical=True
    )

    # Usage
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    builder = builder.add_extension(
        x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH, x509.OID_SERVER_AUTH]),
        critical=False
    )

    # SANs
    sans = list()
    for san in args.alternative_names:
        if fullmatch(REGEXP_IP_ADDR, san) is not None:
            sans.append(x509.IPAddress(ip_address(san)))
        else:
            sans.append(x509.DNSName(san))

    if len(sans) > 0:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(args.common_name), *sans]), 
            critical=False
        )

    # Misc
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    cert_file = "{}.crt".format(args.common_name)

    with open(cert_file, "wb") as f:
        file_content = cert.public_bytes(encoding=serialization.Encoding.PEM)
        f.write(file_content)

    print("Certificate written to {}".format(cert_file))


if __name__ == "__main__":
    main()
