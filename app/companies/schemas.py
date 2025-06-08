from marshmallow import Schema, fields

class ApproveCompanySchema(Schema):
    name = fields.Str(required=True)
