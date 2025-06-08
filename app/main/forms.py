from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, FileField, SubmitField, IntegerField # Added IntegerField
from wtforms.validators import DataRequired, Optional, Length, Regexp
from flask_wtf.file import FileAllowed
from app.utils.files import ALLOWED_IMAGE_EXTENSIONS

class EventForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=128)])
    description = TextAreaField('Description', validators=[DataRequired()])
    # Changed to StringField. Regex for 'YYYY-MM-DDTHH:MM:SS' could be r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$'
    date = StringField('Event Date and Time (YYYY-MM-DDTHH:MM:SS)', validators=[DataRequired(), Length(min=19, max=19)])
    category_id = SelectField('Category', coerce=int, default=0, validators=[Optional()]) # Default to 0 for 'Uncategorized'
    image = FileField('Event Image', validators=[
        Optional(),
        FileAllowed(ALLOWED_IMAGE_EXTENSIONS, 'Images only!')
    ])
    gift_card_amount_cents = IntegerField('Gift Card Amount (in cents)', validators=[Optional()])
    submit = SubmitField('Submit Event')
