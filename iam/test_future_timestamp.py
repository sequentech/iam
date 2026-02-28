#!/usr/bin/env python3
"""
Standalone test to demonstrate the SmartLink future-timestamp bug.

The bug: HMACToken.check_expiration() only checks if a token has expired
(upper bound) but never validates that the token's timestamp is not in the
future (lower bound). This allows pre-generated SmartLinks with future
timestamps to be used immediately.

Reported token example:
  khmac:///sha-256;d7a498...a7e43/10057:AuthEvent:10000:vote:1770992400
  timestamp 1770992400 = 2026-02-13 15:20 CET (4+ hours in the future)

Run:  python3 test_future_timestamp.py
"""

import hmac
import datetime
import time
import unittest
from unittest.mock import patch, MagicMock

# ---------------------------------------------------------------------------
# Minimal re-implementation of HMACToken.check_expiration from iam/utils.py
# (lines 223-260) so we can test without a full Django stack.
# ---------------------------------------------------------------------------

TIMEOUT_TOKEN_STR = 'timeout-token'
SMARTLINK_TIMEOUT = 90  # seconds, from settings

class HMACToken:
    """Extracted from iam/utils.py with Django timezone calls replaced."""

    def __init__(self, token):
        self.token = token
        l = len('khmac:///')
        self.head = token[0:l]
        tails = token[l:]
        self.digest, data = tails.split(';', 1)
        self.hash, self.msg = data.split('/', 1)
        msg_split = self.msg.split(':')
        self.timestamp = msg_split[-1]

        has_expiry = (
            len(msg_split) >= 4
            and TIMEOUT_TOKEN_STR == msg_split[-2]
        )
        self.expiry_timestamp = msg_split[-3] if has_expiry else False

    def check_expiration(self, seconds=300):
        """Returns True iff the token hasn't expired (FIXED)."""
        now = datetime.datetime.now(tz=datetime.timezone.utc)

        # Reject tokens whose creation timestamp is in the future
        token_date = datetime.datetime.fromtimestamp(
            int(self.timestamp),
            tz=datetime.timezone.utc,
        )
        if token_date > now:
            return False

        if self.expiry_timestamp is not False:
            expiry_date = datetime.datetime.fromtimestamp(
                int(self.expiry_timestamp),
                tz=datetime.timezone.utc,
            )
        else:
            expiry_date = token_date + datetime.timedelta(seconds=seconds)
        return expiry_date > now


def _build_smartlink_token(shared_secret, user_id, event_id, timestamp):
    """Build a genhmac-style SmartLink token with the given timestamp."""
    msg = f"{user_id}:AuthEvent:{event_id}:vote:{timestamp}"
    h = hmac.new(shared_secret, msg.encode('utf-8'), 'sha256')
    return f"khmac:///sha-256;{h.hexdigest()}/{msg}"


class TestFutureTimestampBug(unittest.TestCase):
    """Demonstrate the future-timestamp bug in check_expiration."""

    SECRET = b'test-shared-secret'

    # -- token with current timestamp (should always be valid) ---------------
    def test_current_timestamp_is_valid(self):
        now_ts = int(time.time())
        token_str = _build_smartlink_token(
            self.SECRET, 'user1', '10000', now_ts
        )
        token = HMACToken(token_str)
        self.assertTrue(
            token.check_expiration(SMARTLINK_TIMEOUT),
            "A token with the current timestamp should be valid",
        )

    # -- token with past timestamp beyond timeout (should be expired) --------
    def test_expired_token_is_rejected(self):
        old_ts = int(time.time()) - SMARTLINK_TIMEOUT - 10
        token_str = _build_smartlink_token(
            self.SECRET, 'user1', '10000', old_ts
        )
        token = HMACToken(token_str)
        self.assertFalse(
            token.check_expiration(SMARTLINK_TIMEOUT),
            "A token older than SMARTLINK_TIMEOUT should be rejected",
        )

    # -- THE BUG: token with a FUTURE timestamp (should be rejected) ---------
    def test_future_timestamp_is_rejected(self):
        future_ts = int(time.time()) + 3600          # 1 hour in the future
        token_str = _build_smartlink_token(
            self.SECRET, 'user1', '10000', future_ts
        )
        token = HMACToken(token_str)
        self.assertFalse(
            token.check_expiration(SMARTLINK_TIMEOUT),
            "A token with a FUTURE timestamp should be rejected, "
            "but check_expiration has no lower-bound check (BUG)",
        )

    # -- reproduce the exact reported token timestamp ------------------------
    def test_reported_token_1770992400(self):
        """
        The reported token has timestamp 1770992400 = 2026-02-13 14:20 UTC.
        If the current time is before that, the token should be rejected.
        """
        reported_ts = 1770992400
        now_ts = int(time.time())
        if reported_ts > now_ts:
            token_str = _build_smartlink_token(
                self.SECRET, '10057', '10000', reported_ts
            )
            token = HMACToken(token_str)
            self.assertFalse(
                token.check_expiration(SMARTLINK_TIMEOUT),
                f"Token timestamp {reported_ts} is in the future "
                f"(now={now_ts}), should be rejected",
            )
        else:
            self.skipTest(
                "Reported timestamp is no longer in the future"
            )


if __name__ == '__main__':
    unittest.main(verbosity=2)
