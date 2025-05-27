
from flask import Blueprint, request, jsonify
from app.models import Company
from app.extensions import db

companies_bp = Blueprint('companies', __name__)

# Simple admin token (in production, use real authentication)
ADMIN_TOKEN = "my-secret-admin-token"


@companies_bp.route('/pending', methods=['GET'])
def list_pending_companies():
    token = request.headers.get('Authorization')
    if token != f"Bearer {ADMIN_TOKEN}":
        return jsonify({'error': 'Unauthorized'}), 403

    pending = Company.query.filter_by(approved=False).all()
    result = [{'id': c.id, 'name': c.name} for c in pending]
    return jsonify(result), 200


@companies_bp.route('/approve', methods=['POST'])
def approve_company():
    token = request.headers.get('Authorization')
    if token != f"Bearer {ADMIN_TOKEN}":
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    company_name = data.get('name')

    if not company_name:
        return jsonify({'error': 'Missing company name'}), 400

    company = Company.query.filter_by(name=company_name).first()
    if not company:
        return jsonify({'error': 'Company not found'}), 404

    if company.approved:
        return jsonify({'message': 'Company already approved'}), 200

    company.approved = True
    try:
        db.session.commit()
        return jsonify({'message': f'Company {company_name} approved'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to approve company: {str(e)}'}), 500
