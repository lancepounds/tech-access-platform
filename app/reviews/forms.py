from flask_wtf import FlaskForm
from wtforms import SelectField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Optional, NumberRange

class ReviewForm(FlaskForm):
    rating = SelectField(
        'Rating',
        choices=[('1','1'),('2','2'),('3','3'),('4','4'),('5','5')],
        validators=[DataRequired()]
    )
    comment = TextAreaField('Comment', validators=[Optional()])
    submit = SubmitField('Submit Review')

    class Meta:
        csrf = False
