#!/usr/bin/env python3

from argparse import ArgumentParser
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from re import fullmatch
from sys import exit as sys_exit

from cryptography import x509
from cryptography.hazmat._oid import ObjectIdentifier
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import types
from cryptography.x509.oid import NameOID

from . import utils

REGEXP_IP_ADDR = r"(\d{1,3}\.){3}\d{1,3}"


def load_private_key(file: str):
    """Load a PEM private key from disk."""
    pkey_bytes = Path(file).read_bytes()
    return serialization.load_pem_private_key(pkey_bytes, password=None)


def get_subject_oid_attribute(cert: x509.Certificate, oid: ObjectIdentifier):
    """Return the first subject value for an OID, or an empty string."""
    attrs = cert.subject.get_attributes_for_oid(oid)
    if len(attrs) > 0:
        return attrs[0].value
    return ""


def generate_cert(
    ca_key: types.CertificateIssuerPrivateKeyTypes,
    ca_cert: x509.Certificate,
    common_name: str,
    private_key: types.CertificateIssuerPrivateKeyTypes | None = None,
    alternative_names: list[str] | None = None,
    expiry_date: datetime | None = None,
) -> x509.Certificate:
    """
    Generate a certificate signed by the provided CA.

    :param ca_key: Private key for the signing CA.
    :param ca_cert: Certificate for the signing CA.
    :param common_name: Common name for the generated certificate.
    :param alternative_names: Optional SAN entries for the certificate.
    :param private_key: Private key for the generated certificate.
    :param expiry_date: Optional certificate expiry timestamp.
    :returns: The signed certificate object.
    """
    sans = alternative_names if alternative_names is not None else list()

    if private_key is None:
        private_key = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=2048
        )

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
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Self-signed
    builder = builder.subject_name(ca_name).issuer_name(ca_cert.subject)

    # Dates
    builder = utils.set_cert_dates(builder, expiry_date)

    # Not a CA
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
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
            decipher_only=False,
        ),
        critical=True,
    )

    builder = builder.add_extension(
        x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH, x509.OID_SERVER_AUTH]),
        critical=False,
    )

    # SANs
    parsed_sans = list()
    for san in sans:
        if fullmatch(REGEXP_IP_ADDR, san) is not None:
            parsed_sans.append(x509.IPAddress(ip_address(san)))
        else:
            parsed_sans.append(x509.DNSName(san))

    if len(parsed_sans) > 0:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name), *parsed_sans]),
            critical=False,
        )

    # Misc
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)

    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())


def main():
    """Parse CLI arguments and generate a signed certificate."""
    argparser = ArgumentParser(description="Generate a cert given a CA")
    argparser.add_argument("ca_key", help="The path to the private key for the signing CA")
    argparser.add_argument("ca_cert", help="The path to the certificate for the signing CA")
    argparser.add_argument("common_name", help="The certificate's common name")
    argparser.add_argument(
        "-a",
        "--alternative-name",
        dest="alternative_names",
        nargs="+",
        help="Alternative names for the certificate",
        default=list(),
    )
    argparser.add_argument(
        "-k",
        "--private-key",
        help="The private key used to sign the certificate",
        default=None,
    )
    argparser.add_argument(
        "-d",
        "--expiry-date",
        help="Expiry date conforming to iso-8601 (2007-04-05T14:30Z)",
        type=datetime.fromisoformat,
        default=None,
    )
    args = argparser.parse_args()

    try:
        if args.private_key is not None:
            private_key_path = Path(args.private_key)
            if not private_key_path.exists():
                raise FileNotFoundError(f"Private key {args.private_key} does not exist")

            try:
                private_key = load_private_key(args.private_key)
            except Exception as exc:
                raise ValueError(f"Invalid key file {args.private_key}: {exc}") from exc
        else:
            private_key_path = Path(f"{args.common_name}.key")
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            private_key_path.touch()
            private_key_path.chmod(0o600)
            private_key_path.write_bytes(private_key_bytes)

        ca_key_path = Path(args.ca_key)
        if not ca_key_path.exists():
            raise FileNotFoundError(f"CA key {args.ca_key} not found")

        ca_cert_path = Path(args.ca_cert)
        if not ca_cert_path.exists():
            raise FileNotFoundError(f"CA cert {args.ca_cert} not found")

        try:
            ca_key = load_private_key(args.ca_key)
        except Exception as exc:
            raise ValueError(f"Invalid CA key file {args.ca_key}: {exc}") from exc

        try:
            ca_bytes = ca_cert_path.read_bytes()
            ca_cert = x509.load_pem_x509_certificate(ca_bytes)
        except Exception as exc:
            raise ValueError(f"Invalid CA cert file {args.ca_cert}: {exc}") from exc

        cert = generate_cert(
            ca_key=ca_key,
            ca_cert=ca_cert,
            common_name=args.common_name,
            private_key=private_key,
            alternative_names=args.alternative_names,
            expiry_date=args.expiry_date,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(exc)
        sys_exit(1)

    cert_path = Path(f"{args.common_name}.crt")
    cert_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)
    cert_path.write_bytes(cert_bytes)

    if args.private_key is not None:
        print(f"Private key loaded from {private_key_path}")
    else:
        print(f"Private key written to {private_key_path}")

    print(f"Certificate written to {cert_path}")


if __name__ == "__main__":
    main()
