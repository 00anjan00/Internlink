import re
import secrets
from datetime import timedelta
from django.utils import timezone
from .models import EmailOTP

def normalize_np_phone(raw: str) -> str:
    """
    Accepts:
      - 10-digit local: 9812345678
      - +977 + 10-digit: +9779812345678
      - 977 + 10-digit: 9779812345678
      - with spaces/dashes: +977 981-234-5678
    Returns:
      - 10-digit local number only.
    Raises ValueError if invalid.
    """
    if raw is None:
        raise ValueError("Phone is required.")

    s = raw.strip()

    # Keep digits only
    digits = re.sub(r"\D", "", s)

    # If it starts with country code 977 and then 10 digits => 13 total
    if digits.startswith("977") and len(digits) == 13:
        digits = digits[3:]

    # Optional: if user types 0 + 10 digits (like 098...) remove leading 0
    if digits.startswith("0") and len(digits) == 11:
        digits = digits[1:]

    # Must be exactly 10 digits now
    if len(digits) != 10:
        raise ValueError("Phone must be 10 digits (you can also include +977).")

    if not digits.isdigit():
        raise ValueError("Phone must contain only digits.")

    return digits


def looks_like_phone(raw: str) -> bool:
    if not raw:
        return False
    digits = re.sub(r"\D", "", raw)
    return (len(digits) == 10) or (digits.startswith("977") and len(digits) == 13) or (digits.startswith("0") and len(digits) == 11)

def generate_otp_code() -> str:
    # 6 digits, cryptographically strong
    return f"{secrets.randbelow(1000000):06d}"

def create_or_refresh_email_otp(user, minutes_valid=10) -> EmailOTP:
    code = generate_otp_code()
    expires_at = timezone.now() + timedelta(minutes=minutes_valid)

    otp, _ = EmailOTP.objects.update_or_create(
        user=user,
        defaults={
            "code": code,
            "expires_at": expires_at,
            "attempts": 0,
            "is_used": False,
        }
    )
    return otp
