from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, SelectMultipleField, SubmitField, BooleanField # Added BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional

class CompanyRegistrationForm(FlaskForm):
    company_name = StringField('Company Name', validators=[DataRequired(), Length(max=100)])
    contact_email = StringField('Contact Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    contact_name = StringField('Primary Contact Name', validators=[DataRequired(), Length(max=100)])
    contact_title = StringField('Contact Title/Role', validators=[Optional(), Length(max=100)])
    phone = StringField('Phone Number', validators=[Optional(), Length(max=20)])
    website = StringField('Website', validators=[Optional(), Length(max=255)])
    address = TextAreaField('Company Address', validators=[Optional()])
    company_description = TextAreaField('Company Description', validators=[DataRequired()])

    industry_choices = [
        ('', 'Select Industry'),
        ('technology', 'Technology'),
        ('healthcare', 'Healthcare'),
        ('education', 'Education'),
        ('finance', 'Finance'),
        ('retail', 'Retail'),
        ('manufacturing', 'Manufacturing'),
        ('consulting', 'Consulting'),
        ('nonprofit', 'Non-Profit'),
        ('other', 'Other')
    ]
    industry = SelectField('Industry', choices=industry_choices, validators=[Optional()])

    company_size_choices = [
        ('', 'Select Size'),
        ('1-10', '1-10 employees'),
        ('11-50', '11-50 employees'),
        ('51-200', '51-200 employees'),
        ('201-1000', '201-1000 employees'),
        ('1000+', '1000+ employees')
    ]
    company_size = SelectField('Company Size', choices=company_size_choices, validators=[Optional()])

    products_services = TextAreaField('Products & Services', validators=[Optional()])
    accessibility_goals = TextAreaField('Accessibility Goals', validators=[Optional()])

    interest_choices = [
        ('web_accessibility', 'Web Accessibility'),
        ('mobile_accessibility', 'Mobile Accessibility'),
        ('assistive_tech', 'Assistive Technology'),
        ('usability_testing', 'Usability Testing'),
        ('cognitive_accessibility', 'Cognitive Accessibility'),
        ('visual_accessibility', 'Visual Accessibility'),
        ('auditory_accessibility', 'Auditory Accessibility'),
        ('motor_accessibility', 'Motor Accessibility')
    ]
    interests = SelectMultipleField('Areas of Interest', choices=interest_choices, coerce=str, validators=[Optional()])

    experience_choices = [
        ('', 'Select Status'),
        ('none', 'No previous accessibility testing'),
        ('basic', 'Basic accessibility considerations'),
        ('intermediate', 'Some accessibility testing done'),
        ('advanced', 'Comprehensive accessibility program')
    ]
    accessibility_experience = SelectField('Current Accessibility Status', choices=experience_choices, validators=[Optional()])

    compliance_choices = [
        ('', 'Select Requirements'),
        ('wcag_aa', 'WCAG 2.1 AA'),
        ('wcag_aaa', 'WCAG 2.1 AAA'),
        ('ada', 'ADA Compliance'),
        ('section_508', 'Section 508'),
        ('multiple', 'Multiple Standards'),
        ('unsure', 'Not Sure')
    ]
    compliance_requirements = SelectField('Compliance Requirements', choices=compliance_choices, validators=[Optional()])

    timeline_choices = [
        ('', 'Select Timeline'),
        ('asap', 'As soon as possible'),
        ('1_month', 'Within 1 month'),
        ('3_months', 'Within 3 months'),
        ('6_months', 'Within 6 months'),
        ('ongoing', 'Ongoing partnership')
    ]
    testing_timeline = SelectField('Preferred Testing Timeline', choices=timeline_choices, validators=[Optional()])

    budget_choices = [
        ('', 'Select Budget Range'),
        ('under_1k', 'Under $1,000'),
        ('1k_5k', '$1,000 - $5,000'),
        ('5k_10k', '$5,000 - $10,000'),
        ('10k_25k', '$10,000 - $25,000'),
        ('25k_plus', '$25,000+'),
        ('discuss', 'Prefer to discuss')
    ]
    testing_budget = SelectField('Estimated Testing Budget', choices=budget_choices, validators=[Optional()])
    terms_agreement = BooleanField('I agree to the terms and conditions', validators=[DataRequired(message="You must agree to the terms and conditions.")])
    submit = SubmitField('Register Company')
