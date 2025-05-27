
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
