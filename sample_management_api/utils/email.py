from django.conf import settings
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class Util:
    def send_email(data):
        # port = 587  # For starttls
        # smtp_server = "smtp.gmail.com"
        sender_email = settings.DEFAULT_FROM_EMAIL
        receiver_email = data['to_email']
        password = settings.EMAIL_HOST_PASSWORD
        message = MIMEMultipart("alternative")
        message["Subject"] = data["email_subject"]
        message["From"] = sender_email
        message["To"] = receiver_email
        content = data["email_body"]
        text = MIMEText(content, "plain")
        message.attach(text)

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(
                sender_email, receiver_email, message.as_string()
            )
