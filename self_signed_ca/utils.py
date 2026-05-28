import datetime

from cryptography import x509
from zoneinfo import ZoneInfo


UTC = ZoneInfo("UTC")


def set_cert_dates(builder: x509.CertificateBuilder, expiry_date: datetime.datetime | None):
    now = datetime.datetime.now(UTC)
    default_expiry_date = now + datetime.timedelta(days=365)
    builder = builder.not_valid_before(now - datetime.timedelta(minutes=1))
    return builder.not_valid_after(default_expiry_date if expiry_date is None else expiry_date)
