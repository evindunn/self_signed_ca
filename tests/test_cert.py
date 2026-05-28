import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from self_signed_ca import ca
from self_signed_ca import cert


def test_generate_cert_builds_signed_certificate(tmp_path, monkeypatch):
    """Generate a certificate signed by the provided CA."""
    monkeypatch.chdir(tmp_path)

    ca_key_path, ca_cert_path = ca.generate_ca(
        common_name="Test Root CA",
        country="US",
        province="New York",
        locality="New York",
        organization="Example Org",
        email="ca@example.com",
        expiry_date=datetime.datetime(2030, 6, 1, 12, 0, 0),
    )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())

    generated_cert = cert.generate_cert(
        ca_key=ca_key,
        ca_cert=ca_cert,
        common_name="service.internal",
        private_key=private_key,
        alternative_names=["api.internal", "127.0.0.1"],
        expiry_date=datetime.datetime(2029, 1, 1, 12, 0, 0),
    )

    assert generated_cert.issuer == ca_cert.subject
    assert generated_cert.subject != generated_cert.issuer
    assert generated_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "service.internal"
    assert generated_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "US"
    assert generated_cert.public_key().public_numbers() == private_key.public_key().public_numbers()

    basic_constraints = generated_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic_constraints.value.ca is False

    subject_alt_name = generated_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = subject_alt_name.value.get_values_for_type(x509.DNSName)
    ip_addresses = subject_alt_name.value.get_values_for_type(x509.IPAddress)
    assert dns_names == ["service.internal", "api.internal"]
    assert [str(ip_address) for ip_address in ip_addresses] == ["127.0.0.1"]


def test_generate_cert_creates_subject_key_when_private_key_is_empty(tmp_path, monkeypatch):
    """Generate a certificate when no subject private key is provided."""
    monkeypatch.chdir(tmp_path)

    ca_key_path, ca_cert_path = ca.generate_ca(
        common_name="Test Root CA",
        country="US",
        province="New York",
        locality="New York",
        organization="Example Org",
        email="ca@example.com",
        expiry_date=datetime.datetime(2030, 6, 1, 12, 0, 0),
    )
    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())

    generated_cert = cert.generate_cert(
        ca_key=ca_key,
        ca_cert=ca_cert,
        common_name="service.internal",
        private_key=None,
        expiry_date=datetime.datetime(2029, 1, 1, 12, 0, 0),
    )

    assert generated_cert.issuer == ca_cert.subject
    assert generated_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "service.internal"
    assert generated_cert.public_key() is not None

    basic_constraints = generated_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic_constraints.value.ca is False
