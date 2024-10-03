import requests
from core.config import settings


def send_email(sender: str, to: list[str], subject: str, text: str):
    return requests.post(
        settings.EMAIL_API,
        auth=("api", settings.MAILGUN_API_TOKEN),
        data={"from": sender, "to": to, "subject": subject, "text": text}
    )


def send_activation_email(to: str, activation_token: str):
    if settings.ENVIRONMENT == "testing":
        return

    text = f"""
Welcome to our platform! Please activate your account by clicking the link below:
{settings.APP_URL}/activate?token={activation_token}
"""
    
    return send_email(
        "Registration <mailgun@signup.javohir.me>",
        to=[to],
        subject="Activate your account",
        text=text,
    )
