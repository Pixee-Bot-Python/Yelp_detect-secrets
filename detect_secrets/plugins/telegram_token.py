"""
This plugin searches for Telegram bot tokens
"""
import re

from ..constants import VerifiedResult
from detect_secrets.plugins.base import RegexBasedDetector
from security import safe_requests


class TelegramBotTokenDetector(RegexBasedDetector):
    """Scans for Telegram bot tokens."""
    secret_type = 'Telegram Bot Token'

    denylist = [
        # refs https://core.telegram.org/bots/api#authorizing-your-bot
        re.compile(r'\d{8,10}:[0-9A-Za-z_-]{35}'),
    ]

    def verify(self, secret: str) -> VerifiedResult:  # pragma: no cover
        response = safe_requests.get(
            'https://api.telegram.org/bot{}/getMe'.format(
                secret,
            ),
        )
        return (
            VerifiedResult.VERIFIED_TRUE
            if response.status_code == 200
            else VerifiedResult.VERIFIED_FALSE
        )
