
from marshmallow import fields, validate, validates, ValidationError
from app.extensions import ma
import re


class CheckCreateSchema(ma.Schema):
    name = fields.String(
        required=True,
        validate=validate.Length(min=1, max=100),
        error_messages={
            "required": "Name is required.",
            "validator_failed": "Name must be between 1 and 100 characters."
        }
    )
    target = fields.String(
        required=True,
        validate=validate.Length(min=1, max=255),
        error_messages={
            "required": "Target is required.",
            "validator_failed": "Target must be between 1 and 255 characters."
        }
    )
    interval_sec = fields.Integer(
        required=True,
        validate=validate.Range(min=5, max=86400),  # 5 seconds to 24 hours
        error_messages={
            "required": "Interval is required.",
            "validator_failed": "Interval must be between 5 seconds and 86400 seconds (24 hours)."
        }
    )

    @validates('target')
    def validate_target_url(self, value):
        # Basic URL validation - must start with http:// or https://
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        if not url_pattern.match(value):
            raise ValidationError('Target must be a valid URL starting with http:// or https://')


class CheckUpdateSchema(ma.Schema):
    name = fields.String(
        validate=validate.Length(min=1, max=100),
        error_messages={
            "validator_failed": "Name must be between 1 and 100 characters."
        }
    )
    target = fields.String(
        validate=validate.Length(min=1, max=255),
        error_messages={
            "validator_failed": "Target must be between 1 and 255 characters."
        }
    )
    interval_sec = fields.Integer(
        validate=validate.Range(min=5, max=86400),
        error_messages={
            "validator_failed": "Interval must be between 5 seconds and 86400 seconds (24 hours)."
        }
    )

    @validates('target')
    def validate_target_url(self, value):
        url_pattern = re.compile(
            r'^https?://'
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
            r'localhost|'
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            r'(?::\d+)?'
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        if not url_pattern.match(value):
            raise ValidationError('Target must be a valid URL starting with http:// or https://')


class CheckResponseSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    name = fields.String()
    target = fields.String()
    interval_sec = fields.Integer()
    created_at = fields.DateTime(format='%Y-%m-%dT%H:%M:%S.%fZ')


class CheckResultCreateSchema(ma.Schema):
    check_id = fields.Integer(
        required=True,
        error_messages={"required": "Check ID is required."}
    )
    status = fields.String(
        required=True,
        validate=validate.OneOf(['success', 'failure', 'timeout', 'error']),
        error_messages={
            "required": "Status is required.",
            "validator_failed": "Status must be one of: success, failure, timeout, error."
        }
    )
    latency_ms = fields.Integer(
        validate=validate.Range(min=0),
        allow_none=True,
        error_messages={
            "validator_failed": "Latency must be a positive integer or null."
        }
    )


class CheckResultResponseSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    check_id = fields.Integer()
    status = fields.String()
    latency_ms = fields.Integer(allow_none=True)
    timestamp = fields.DateTime(format='%Y-%m-%dT%H:%M:%S.%fZ')
