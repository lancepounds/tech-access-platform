from flask import render_template, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from app.extensions import db
from app.models import Category, Event # Added Event model for checking associations
from .forms import CategoryForm, DeleteCategoryForm # Added DeleteCategoryForm
from . import categories_bp

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
            # Redirect to list_categories after creation
            return redirect(url_for('categories.list_categories'))

    return render_template('create_category.html', form=form)

@categories_bp.route('/<int:category_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    # Admin check - ensure current_user.is_admin exists and is correct
    # Assuming is_admin is now a boolean attribute on the User model
    if not hasattr(current_user, 'is_admin') or not current_user.is_admin:
        abort(403)

    category = Category.query.get_or_404(category_id)
    form = CategoryForm(obj=category) # For GET, pre-populate with category data

    if request.method == 'POST': # Explicitly check for POST for clarity
        # For POST, create a new form instance with incoming data,
        # but also pass obj=category to keep data if form is invalid.
        form = CategoryForm(request.form, obj=category)
        if form.validate_on_submit():
            new_name = form.name.data
            # Check if new name already exists for a *different* category
            existing_category = Category.query.filter(
                Category.name == new_name,
                Category.id != category_id
            ).first()

            if existing_category:
                flash('Category name already exists.', 'danger')
            else:
                category.name = new_name
                db.session.commit()
                flash('Category updated successfully.', 'success')
                return redirect(url_for('categories.list_categories')) # Redirect to list view

    # For GET request, or if POST validation fails, render edit form
    # If it's a GET, form was already populated with obj=category.
    # If it's a POST that failed validation, form contains submitted data & errors.
    return render_template('edit_category.html', form=form, category=category)

@categories_bp.route('/', methods=['GET'])
@login_required
# For now, any logged-in user can see the list.
# Could be restricted to admin/company if needed later via:
# if current_user.role not in ('admin', 'company'): abort(403)
def list_categories():
    categories = Category.query.order_by(Category.name).all()
    is_admin_user = hasattr(current_user, 'is_admin') and current_user.is_admin
    delete_form = DeleteCategoryForm() # For delete buttons
    return render_template('list_categories.html', categories=categories, is_admin_user=is_admin_user, delete_form=delete_form)

@categories_bp.route('/<int:category_id>/delete', methods=['POST'])
@login_required
def delete_category(category_id):
    if not hasattr(current_user, 'is_admin') or not current_user.is_admin:
        abort(403)

    form = DeleteCategoryForm() # For CSRF validation
    if form.validate_on_submit(): # Process if CSRF is valid
        category = Category.query.get_or_404(category_id)

        # Check for associated events
        if category.events: # Assumes 'events' is the backref
            flash('Cannot delete category: It is associated with existing events. Please reassign or delete those events first.', 'danger')
        else:
            db.session.delete(category)
            db.session.commit()
            flash('Category deleted successfully.', 'success')
    else:
        # This case might happen if CSRF token is missing or invalid
        flash('Invalid request for deletion.', 'danger')

    return redirect(url_for('categories.list_categories'))
