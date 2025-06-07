from flask import Blueprint, render_template, request, current_app, redirect, url_for, flash
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import os, uuid
from app.extensions import db
from app.models import User, RSVP, Event, Waitlist
from app.users.forms import ProfileForm, CancelRSVPForm

users_bp = Blueprint('users', __name__)

@users_bp.route('/users/profile', methods=['GET', 'POST'])
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


@users_bp.route('/my-rsvps')
@login_required
def my_rsvps():
    """Display events the current user has RSVP'd to."""
    user = current_user
    rsvps = RSVP.query.filter_by(user_id=user.id).all()
    events = [rsvp.event for rsvp in rsvps if rsvp.event]
    waitlists = Waitlist.query.filter_by(user_id=user.id).order_by(Waitlist.created_at).all()
    form = CancelRSVPForm()
    return render_template('my_rsvps.html', events=events, waitlists=waitlists, form=form, Waitlist=Waitlist)


@users_bp.route('/cancel-rsvp/<int:event_id>', methods=['POST'])
@login_required
def cancel_rsvp(event_id: int):
    """Allow a user to cancel their RSVP for a given event."""
    rsvp = RSVP.query.filter_by(user_id=current_user.id, event_id=str(event_id)).first()
    if rsvp:
        db.session.delete(rsvp)
        next_wait = Waitlist.query.filter_by(event_id=str(event_id)).order_by(Waitlist.created_at).first()
        if next_wait:
            new_rsvp = RSVP(user_id=next_wait.user_id, event_id=str(event_id))
            db.session.delete(next_wait)
            db.session.add(new_rsvp)
        db.session.commit()
        flash('RSVP cancelled.', 'success')
    return redirect(url_for('users.my_rsvps'))
