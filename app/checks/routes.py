
from flask import Blueprint, request, jsonify
from marshmallow import ValidationError
from app.models import Check, CheckResult
from app.extensions import db
from app.checks.schemas import (
    CheckCreateSchema, 
    CheckUpdateSchema, 
    CheckResponseSchema,
    CheckResultCreateSchema,
    CheckResultResponseSchema
)

checks_bp = Blueprint('checks', __name__)

# Initialize schemas
check_create_schema = CheckCreateSchema()
check_update_schema = CheckUpdateSchema()
check_response_schema = CheckResponseSchema()
check_results_response_schema = CheckResponseSchema(many=True)
check_result_create_schema = CheckResultCreateSchema()
check_result_response_schema = CheckResultResponseSchema()


@checks_bp.route('', methods=['POST'])
def create_check():
    try:
        data = check_create_schema.load(request.get_json() or {})
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400
    
    check = Check(
        name=data['name'],
        target=data['target'],
        interval_sec=data['interval_sec']
    )
    
    try:
        db.session.add(check)
        db.session.commit()
        return jsonify(check_response_schema.dump(check)), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to create check: {str(e)}'}), 500


@checks_bp.route('', methods=['GET'])
def get_checks():
    checks = Check.query.all()
    return jsonify(check_results_response_schema.dump(checks)), 200


@checks_bp.route('/<int:check_id>', methods=['GET'])
def get_check(check_id):
    check = Check.query.get(check_id)
    if not check:
        return jsonify({'error': 'Check not found'}), 404
    
    return jsonify(check_response_schema.dump(check)), 200


@checks_bp.route('/<int:check_id>', methods=['PUT'])
def update_check(check_id):
    check = Check.query.get(check_id)
    if not check:
        return jsonify({'error': 'Check not found'}), 404
    
    try:
        data = check_update_schema.load(request.get_json() or {})
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400
    
    # Update fields if provided
    for field, value in data.items():
        setattr(check, field, value)
    
    try:
        db.session.commit()
        return jsonify(check_response_schema.dump(check)), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to update check: {str(e)}'}), 500


@checks_bp.route('/<int:check_id>', methods=['DELETE'])
def delete_check(check_id):
    check = Check.query.get(check_id)
    if not check:
        return jsonify({'error': 'Check not found'}), 404
    
    try:
        db.session.delete(check)
        db.session.commit()
        return jsonify({'message': 'Check deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete check: {str(e)}'}), 500


@checks_bp.route('/<int:check_id>/results', methods=['POST'])
def create_check_result(check_id):
    # Verify check exists
    check = Check.query.get(check_id)
    if not check:
        return jsonify({'error': 'Check not found'}), 404
    
    try:
        data = check_result_create_schema.load(request.get_json() or {})
        # Override check_id from URL parameter
        data['check_id'] = check_id
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400
    
    check_result = CheckResult(
        check_id=data['check_id'],
        status=data['status'],
        latency_ms=data.get('latency_ms')
    )
    
    try:
        db.session.add(check_result)
        db.session.commit()
        return jsonify(check_result_response_schema.dump(check_result)), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to create check result: {str(e)}'}), 500


@checks_bp.route('/<int:check_id>/results', methods=['GET'])
def get_check_results(check_id):
    # Verify check exists
    check = Check.query.get(check_id)
    if not check:
        return jsonify({'error': 'Check not found'}), 404
    
    # Get query parameters for pagination and filtering
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    since = request.args.get('since')
    
    # Limit maximum results per request
    limit = min(limit, 100)
    
    # Build query
    query = CheckResult.query.filter_by(check_id=check_id)
    
    # Add timestamp filter if 'since' parameter is provided
    if since:
        try:
            from datetime import datetime
            # Parse ISO timestamp
            since_datetime = datetime.fromisoformat(since.replace('Z', '+00:00'))
            query = query.filter(CheckResult.timestamp >= since_datetime)
        except ValueError:
            return jsonify({'error': 'Invalid timestamp format. Use ISO format (e.g., 2024-01-01T00:00:00Z)'}), 400
    
    results = query.order_by(CheckResult.timestamp.desc())\
                  .offset(offset)\
                  .limit(limit)\
                  .all()
    
    return jsonify(CheckResultResponseSchema(many=True).dump(results)), 200
