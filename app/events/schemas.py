from marshmallow import Schema, fields, validate

class EventSchema(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=1, max=128))
    description = fields.Str(required=True)
    # Using DateTime field, format might need adjustment if parsing issues arise.
    # It defaults to ISO 8601, which YYYY-MM-DDTHH:MM:SS is a part of.
    date = fields.DateTime(format='%Y-%m-%dT%H:%M:%S', required=True)
    # Optional fields can be added later if needed, e.g., category_id, capacity

class RsvpSchema(Schema):
    payment_source = fields.Str(required=True)

class IssueGiftSchema(Schema):
    user_id = fields.Str(required=True)
    payment_source = fields.Str(required=True)
    # Defaulting to 1000 cents ($10) as per previous logic if not provided
    # Changed 'missing' to 'load_default' for Marshmallow 2 compatibility
    amount_cents = fields.Int(required=False, load_default=1000)
