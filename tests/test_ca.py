import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from self_signed_ca import ca


def test_generate_ca_writes_matching_key_and_certificate(tmp_path, monkeypatch):
    """Generate a CA certificate and matching private key files."""
    monkeypatch.chdir(tmp_path)

    key_path, cert_path = ca.generate_ca(
        common_name="Test Root CA",
        country="US",
        province="New York",
        locality="New York",
        organization="Example Org",
        email="ca@example.com",
        expiry_date=datetime.datetime(2030, 6, 1, 12, 0, 0),
    )

    assert key_path.name == "Test Root CA.key"
    assert cert_path.name == "Test Root CA.crt"
    assert key_path.exists()
    assert cert_path.exists()

    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())

    assert cert.subject == cert.issuer
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Test Root CA"
    assert cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "US"
    assert cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == "New York"
    assert cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value == "New York"
    assert cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "Example Org"
    assert cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value == "ca@example.com"
    assert cert.public_key().public_numbers() == private_key.public_key().public_numbers()

    basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic_constraints.value.ca is True
