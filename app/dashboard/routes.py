
from flask import Blueprint, render_template, abort, session
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from app.models import Event, Company, User
from app.extensions import db

dash_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")

def require_role(required_role):
    """Check if the current user has the required role"""
    # Check session for role (for web interface)
    if 'role' in session:
        if session['role'] != required_role:
            abort(403)
        return
    
    # Check JWT claims (for API access)
    try:
        claims = get_jwt()
        if claims.get("role") != required_role:
            abort(403)
    except:
        abort(401)

@dash_bp.route("/member")
def member_dashboard():
    """Dashboard for regular members/users"""
    # Check if user is logged in via session or JWT
    if 'role' in session:
        require_role("user")
    else:
        # For JWT access
        jwt_required()(lambda: None)()
        require_role("user")
    
    # Get all upcoming events
    events = Event.query.order_by(Event.date.desc()).all()
    return render_template("member_dashboard.html", events=events)

@dash_bp.route("/company")
def company_dashboard():
    """Dashboard for companies"""
    # Check if user is logged in via session or JWT
    if 'role' in session:
        require_role("company")
        company_id = session.get('company_id')
    else:
        # For JWT access
        jwt_required()(lambda: None)()
        require_role("company")
        claims = get_jwt()
        company_id = claims.get("company_id")
    
    # Get company details
    company = Company.query.get(company_id)
    if not company:
        abort(404)
    
    # Get company's events if any
    events = Event.query.filter_by(company_id=str(company_id)).order_by(Event.date.desc()).all()
    
    return render_template("company_dashboard.html", company=company, events=events)
def company_dashboard():
    """Dashboard for companies"""
    # Check if company is logged in via session or JWT
    if 'role' in session:
        require_role("company")
        company_name = session.get('email')  # Companies use name as email
    else:
        # For JWT access
        jwt_required()(lambda: None)()
        require_role("company")
        company_name = get_jwt_identity()
    
    # Get company's events
    company = Company.query.filter_by(name=company_name).first()
    if not company:
        abort(404)
    
    my_events = Event.query.filter_by(company_id=company.id).order_by(Event.date.desc()).all()
    return render_template("company_dashboard.html", events=my_events, company=company)
