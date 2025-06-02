
from marshmallow import fields, validate
from app.extensions import ma


class RegistrationSchema(ma.Schema):
    email = fields.Email(required=True,
        error_messages={
          "required": "Email is required.",
          "invalid": "Not a valid email address."
        })
    password = fields.String(required=True,
        validate=validate.Length(min=8),
        error_messages={
          "required": "Password is required.",
          "validator_failed": "Password must be at least 8 characters."
        })
    
    # Personal Information
    firstName = fields.String(required=True, validate=validate.Length(min=1, max=50),
        error_messages={
          "required": "First name is required.",
          "validator_failed": "First name must be 1-50 characters."
        })
    lastName = fields.String(required=True, validate=validate.Length(min=1, max=50),
        error_messages={
          "required": "Last name is required.",
          "validator_failed": "Last name must be 1-50 characters."
        })
    phone = fields.String(validate=validate.Length(max=20))
    
    # Accessibility Information
    disabilities = fields.List(fields.String())
    assistiveTech = fields.String()
    
    # Experience & Interests
    techExperience = fields.String(required=True,
        validate=validate.OneOf(['beginner', 'intermediate', 'advanced', 'expert']),
        error_messages={
          "required": "Technology experience level is required.",
          "validator_failed": "Please select a valid experience level."
        })
    interests = fields.List(fields.String())
    
    # Communication Preferences
    emailNotifications = fields.Boolean(missing=True)
    newsletter = fields.Boolean(missing=False)
    
    # Communication Preferences
    emailNotifications = fields.Boolean()
    newsletter = fields.Boolean()
    terms = fields.Boolean(required=True,
        error_messages={
          "required": "You must agree to the terms and conditions."
        })


class LoginSchema(ma.Schema):
    email = fields.Email(required=True,
        error_messages={"required": "Email is required."})
    password = fields.String(required=True,
        error_messages={"required": "Password is required."})


class ProfileSchema(ma.Schema):
    id = fields.Int(dump_only=True)
    email = fields.Email()
    role = fields.String()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()
