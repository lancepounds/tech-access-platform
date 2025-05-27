
from flask import Blueprint, request, jsonify
from app.models import Check
from app.extensions import db

checks_bp = Blueprint('checks', __name__)


@checks_bp.route('', methods=['POST'])
def create_check():
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    required_fields = ['name', 'target', 'interval_sec']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    check = Check(
        name=data['name'],
        target=data['target'],
        interval_sec=data['interval_sec']
    )
    
    try:
        db.session.add(check)
        db.session.commit()
        return jsonify({
            'id': check.id,
            'name': check.name,
            'target': check.target,
            'interval_sec': check.interval_sec,
            'created_at': check.created_at.isoformat()
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to create check: {str(e)}'}), 500


@checks_bp.route('', methods=['GET'])
def get_checks():
    checks = Check.query.all()
    return jsonify([{
        'id': check.id,
        'name': check.name,
        'target': check.target,
        'interval_sec': check.interval_sec,
        'created_at': check.created_at.isoformat()
    } for check in checks]), 200


@checks_bp.route('/<int:check_id>', methods=['GET'])
def get_check(check_id):
    check = Check.query.get(check_id)
    if not check:
        return jsonify({'error': 'Check not found'}), 404
    
    return jsonify({
        'id': check.id,
        'name': check.name,
        'target': check.target,
        'interval_sec': check.interval_sec,
        'created_at': check.created_at.isoformat()
    }), 200


@checks_bp.route('/<int:check_id>', methods=['PUT'])
def update_check(check_id):
    check = Check.query.get(check_id)
    if not check:
        return jsonify({'error': 'Check not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Update fields if provided
    if 'name' in data:
        check.name = data['name']
    if 'target' in data:
        check.target = data['target']
    if 'interval_sec' in data:
        check.interval_sec = data['interval_sec']
    
    try:
        db.session.commit()
        return jsonify({
            'id': check.id,
            'name': check.name,
            'target': check.target,
            'interval_sec': check.interval_sec,
            'created_at': check.created_at.isoformat()
        }), 200
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
