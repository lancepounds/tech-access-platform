
from flask import Blueprint, request, jsonify, current_app as app
from werkzeug.exceptions import BadRequest, Unauthorized
from flask_jwt_extended import create_access_token
import bcrypt  # or use app.bcrypt

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    email = data.get("email")
    pwd = data.get("password")
    role = data.get("role")
    if not email or not pwd or role not in ("member", "company"):
        raise BadRequest("email, password, and role (member/company) required")
    pw_hash = app.bcrypt.generate_password_hash(pwd).decode()
    resp = app.supabase.table("users").insert({
        "email": email,
        "password_hash": pw_hash,
        "role": role
    }).execute()
    if resp.error:
        return jsonify({"msg": resp.error.message}), 400
    return jsonify({"msg": "user created"}), 201

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    pwd = data.get("password")
    if not email or not pwd:
        raise BadRequest("email and password required")
    result = app.supabase.table("users").select("*").eq("email", email).single().execute()
    user = result.data
    if result.error or not user:
        raise Unauthorized("invalid credentials")
    if not app.bcrypt.check_password_hash(user["password_hash"], pwd):
        raise Unauthorized("invalid credentials")
    token = create_access_token(identity=user["id"], additional_claims={"role": user["role"]})
    return jsonify(access_token=token), 200
