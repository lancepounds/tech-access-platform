from flask import Blueprint, render_template, request, current_app, redirect, url_for, flash
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import os, uuid
from app.extensions import db
from app.models import User
from app.users.forms import ProfileForm

users_bp = Blueprint('users', __name__, url_prefix='/users')

@users_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user
    form = ProfileForm(obj=user)

    if form.validate_on_submit():
        user.name = form.name.data
        user.bio = form.bio.data

        avatar_file = form.avatar.data
        if avatar_file:
            filename = secure_filename(avatar_file.filename)
            unique_name = f"{uuid.uuid4().hex}_{filename}"
            upload_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'profiles')
            os.makedirs(upload_folder, exist_ok=True)
            avatar_path = os.path.join(upload_folder, unique_name)
            avatar_file.save(avatar_path)
            user.avatar_filename = unique_name

        db.session.commit()
        flash('Profile updated!', 'success')
        return redirect(url_for('users.profile'))

    return render_template('profile.html', form=form, user=user)
