import click
from flask.cli import with_appcontext
from app.models import User
from app.extensions import db

@click.command("grant-admin")
@click.argument("email")
@with_appcontext
def grant_admin_command(email):
    """Grants admin privileges to a user."""
    user = User.query.filter_by(email=email).first()
    if user:
        user.is_admin = True
        db.session.commit()
        print(f"User {email} is now an admin.")
    else:
        print(f"User {email} not found.")
