# accounts/emails.py
from django.core.mail import send_mail
from django.conf import settings

def send_verification_code_email(user, code: str):
    subject = "InternLink Email Verification Code"
    message = (
        f"Your InternLink verification code is: {code}\n\n"
        "This code will expire in 10 minutes.\n"
        "If you didn’t create this account, ignore this email."
    )

    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )
