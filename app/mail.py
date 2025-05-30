
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from flask import current_app as app

def send_email(to_email, subject, html_content):
    if app.config["SENDGRID_MOCK"]:
        app.logger.info(f"Mock email to {to_email}: {subject}")
        return True
    message = Mail(
        from_email="no-reply@techaccess.io",
        to_emails=to_email,
        subject=subject,
        html_content=html_content
    )
    sg = SendGridAPIClient(app.config["SENDGRID_API_KEY"])
    response = sg.send(message)
    return response.status_code < 300
