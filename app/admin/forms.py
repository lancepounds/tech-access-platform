from flask_wtf import FlaskForm
from wtforms import SubmitField

class ApproveCompanyForm(FlaskForm):
    submit_approve = SubmitField('Approve')

class DenyCompanyForm(FlaskForm):
    submit_deny = SubmitField('Deny')

class ToggleAdminForm(FlaskForm):
    submit_toggle = SubmitField('Toggle Admin')
