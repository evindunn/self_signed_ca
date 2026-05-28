import datetime
import unittest.mock

from self_signed_ca import utils


class FrozenDateTime(datetime.datetime):
    """Frozen datetime used to make certificate date tests deterministic."""

    @classmethod
    def now(cls, tz=None):
        """Return a fixed current time for tests."""
        return cls(2026, 1, 2, 3, 4, 5, tzinfo=tz)


def test_set_cert_dates_uses_default_expiry_when_missing(monkeypatch):
    """Set the certificate dates using the default one-year expiry."""
    monkeypatch.setattr(utils.datetime, "datetime", FrozenDateTime)

    builder = unittest.mock.Mock()
    dated_builder = unittest.mock.Mock()
    final_builder = unittest.mock.Mock()
    builder.not_valid_before.return_value = dated_builder
    dated_builder.not_valid_after.return_value = final_builder

    result = utils.set_cert_dates(builder, None)

    now = FrozenDateTime.now()
    builder.not_valid_before.assert_called_once_with(now - datetime.timedelta(minutes=1))
    dated_builder.not_valid_after.assert_called_once_with(now + datetime.timedelta(days=365))
    assert result is final_builder


def test_set_cert_dates_uses_explicit_expiry_when_provided(monkeypatch):
    """Set the certificate dates using the provided expiry."""
    monkeypatch.setattr(utils.datetime, "datetime", FrozenDateTime)

    builder = unittest.mock.Mock()
    dated_builder = unittest.mock.Mock()
    final_builder = unittest.mock.Mock()
    builder.not_valid_before.return_value = dated_builder
    dated_builder.not_valid_after.return_value = final_builder
    expiry_date = datetime.datetime(2030, 6, 1, 12, 0, 0)

    result = utils.set_cert_dates(builder, expiry_date)

    builder.not_valid_before.assert_called_once_with(
        FrozenDateTime.now() - datetime.timedelta(minutes=1)
    )
    dated_builder.not_valid_after.assert_called_once_with(expiry_date)
    assert result is final_builder
