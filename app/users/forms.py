from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField, SubmitField
from wtforms.validators import DataRequired, Optional
from flask_wtf.file import FileAllowed
from app.utils.files import ALLOWED_IMAGE_EXTENSIONS, FileSizeLimit # Import the extensions and validator

class ProfileForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    bio = TextAreaField('Bio')
    avatar = FileField(
        'Avatar',
        validators=[
            Optional(),
            FileAllowed(list(ALLOWED_IMAGE_EXTENSIONS), 'Images only!'),
            FileSizeLimit(2 * 1024 * 1024)
        ]
    )
    submit = SubmitField('Save Profile')


class CancelRSVPForm(FlaskForm):
    """Empty form used solely for CSRF protection when cancelling an RSVP."""
    submit = SubmitField('Cancel RSVP')


class WaitlistForm(FlaskForm):
    pass
