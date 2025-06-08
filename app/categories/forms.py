from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length

class CategoryForm(FlaskForm):
    name = StringField('Category Name', validators=[DataRequired(), Length(min=1, max=80)])
    submit = SubmitField('Submit')

class DeleteCategoryForm(FlaskForm):
    submit = SubmitField('Delete')
