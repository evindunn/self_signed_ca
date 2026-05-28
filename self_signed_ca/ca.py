#!/usr/bin/env python3

from argparse import ArgumentParser
from datetime import datetime
from pathlib import Path
from sys import exit as sys_exit

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from . import utils


def generate_ca(
    common_name: str,
    country: str,
    province: str,
    locality: str,
    organization: str,
    email: str,
    private_key_file: str | None = None,
    expiry_date: datetime | None = None,
) -> tuple[Path, Path]:
    """
    Generate a self-signed CA certificate and private key.

    :param common_name: Common name for the CA certificate.
    :param country: Two-letter country code for the CA subject.
    :param province: State or province for the CA subject.
    :param locality: Locality for the CA subject.
    :param organization: Organization name for the CA subject.
    :param email: Contact email for the CA subject.
    :param private_key_file: Optional PEM private key path to reuse.
    :param expiry_date: Optional certificate expiry timestamp.
    :returns: Paths to the private key file and generated certificate file.
    :raises FileNotFoundError: If the provided private key path does not exist.
    :raises ValueError: If the provided private key cannot be loaded.
    """
    if private_key_file is not None:
        private_key_path = Path(private_key_file)
        if not private_key_path.exists():
            raise FileNotFoundError(f"Private key {private_key_file} does not exist")

        try:
            private_key_bytes = private_key_path.read_bytes()
            private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=None,
            )
        except Exception as exc:
            raise ValueError(f"Invalid key file {private_key_file}: {exc}") from exc
    else:
        private_key_path = Path(f"{common_name}.key")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key_path.touch()
        private_key_path.chmod(0o600)
        private_key_path.write_bytes(private_key_bytes)

    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()

    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, province),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Self-signed
    builder = builder.subject_name(ca_name).issuer_name(ca_name)

    # Dates
    builder = utils.set_cert_dates(builder, expiry_date)

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
            decipher_only=False,
        ),
        critical=True,
    )

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )

    builder = builder.add_extension(
        x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH, x509.OID_SERVER_AUTH]),
        critical=False,
    )

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False,
    )

    # Misc
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)

    cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)

    cert_path = Path(f"{common_name}.crt")
    cert_path.write_bytes(cert_pem)

    return private_key_path, cert_path


def main():
    """Parse CLI arguments and generate a self-signed CA."""
    argparser = ArgumentParser(description="Generate a self-signed CA")
    argparser.add_argument("common_name", help="The CA's common name")
    argparser.add_argument("country", help="The CA's 2-letter country code")
    argparser.add_argument("province", help="The CA's spelled-out state/province")
    argparser.add_argument("locality", help="The CA's locality")
    argparser.add_argument("organization", help="The name of the CA's organization")
    argparser.add_argument("email", help="The contact email for the CA")
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
        private_key_path, cert_path = generate_ca(
            common_name=args.common_name,
            country=args.country,
            province=args.province,
            locality=args.locality,
            organization=args.organization,
            email=args.email,
            private_key_file=args.private_key,
            expiry_date=args.expiry_date,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(exc)
        sys_exit(1)

    if args.private_key is not None:
        print(f"Private key loaded from {private_key_path}")
    else:
        print(f"Private key written to {private_key_path}")

    print(f"Certificate written to {cert_path}")


if __name__ == "__main__":
    main()
