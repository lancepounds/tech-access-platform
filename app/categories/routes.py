from flask import render_template, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from app.extensions import db
from app.models import Category
from .forms import CategoryForm  # Relative import
from . import categories_bp      # Import blueprint from package __init__

@categories_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_category():
    if current_user.role not in ('admin', 'company'):
        abort(403)

    form = CategoryForm()
    if form.validate_on_submit():
        name = form.name.data
        existing_category = Category.query.filter_by(name=name).first()
        if existing_category:
            flash('Category already exists.', 'danger')
        else:
            cat = Category(name=name)
            db.session.add(cat)
            db.session.commit()
            flash('Category created successfully!', 'success')
            return redirect(url_for('categories.create_category'))

    return render_template('create_category.html', form=form)
