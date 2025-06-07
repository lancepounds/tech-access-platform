from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from app.extensions import db
from app.models import Category

categories_bp = Blueprint('categories', __name__, url_prefix='/categories')

@categories_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_category():
    if current_user.role not in ('admin', 'company'):
        abort(403)
    if request.method == 'POST':
        name = request.form['name']
        if name:
            cat = Category(name=name)
            db.session.add(cat)
            db.session.commit()
            flash('Category created', 'success')
            return redirect(url_for('categories.create_category'))
    return render_template('create_category.html')
