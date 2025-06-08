from flask import Blueprint, render_template, request, current_app, redirect, url_for, flash
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import os
import uuid
from flask import Blueprint
from flask_mail import Message
from app.extensions import db, mail
from app.models import User, RSVP, Event, Waitlist, Favorite
from app.users.forms import ProfileForm, CancelRSVPForm
from app.utils.files import allowed_image_extension, validate_file_content # Import validators
import logging # For logging save errors

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
        if avatar_file: # form.avatar.data is a FileStorage object if a file was uploaded
            filename = secure_filename(avatar_file.filename)
            # The FileAllowed validator in ProfileForm already checks extensions.
            # If it fails, form.validate_on_submit() will be false, and this part of the code won't run.
            # So, if we are here and avatar_file is present, its extension was allowed by FileAllowed.
            # We still need to validate content.
            if not validate_file_content(avatar_file): # validate_file_content seeks(0)
                flash('Invalid avatar content. File does not appear to be a valid image.', 'danger')
                return redirect(url_for('users.profile'))

            unique_name = f"{uuid.uuid4().hex}_{filename}"
            upload_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'profiles')
            os.makedirs(upload_folder, exist_ok=True)
            avatar_path = os.path.join(upload_folder, unique_name)
            try:
                avatar_file.save(avatar_path)
                user.avatar_filename = unique_name
            except Exception as e:
                logging.error(f"Avatar save error: {e}")
                flash('Could not save avatar. Please try again later.', 'danger')
                # No redirect here, so user stays on form and can try again or just save text fields

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
        event = Event.query.get(event_id)
        db.session.delete(rsvp)
        next_wait = Waitlist.query.filter_by(event_id=str(event_id)).order_by(Waitlist.created_at).first()
        if next_wait:
            new_rsvp = RSVP(user_id=next_wait.user_id, event_id=str(event_id))
            db.session.delete(next_wait)
            db.session.add(new_rsvp)
        db.session.commit()
        msg = Message(
            subject=f"RSVP Cancellation for {event.title}",
            recipients=[current_user.email]
        )
        msg.body = render_template('email/cancellation_confirmation.txt', user=current_user, event=event)
        mail.send(msg)
        flash('RSVP cancelled.', 'success')
    return redirect(url_for('users.my_rsvps'))


@users_bp.route('/favorite/<event_id>', methods=['POST'])
@login_required
def toggle_favorite(event_id):
    """Toggle favorite status for the given event."""
    fav = Favorite.query.filter_by(user_id=current_user.id, event_id=str(event_id)).first()
    if fav:
        db.session.delete(fav)
        db.session.commit()
        flash('Event removed from favorites.', 'success')
    else:
        new_fav = Favorite(user_id=current_user.id, event_id=str(event_id))
        db.session.add(new_fav)
        db.session.commit()
        flash('Event added to favorites.', 'success')
    return redirect(request.referrer or url_for('main.event_detail', event_id=event_id))


@users_bp.route('/users/favorites')
@login_required
def my_favorites():
    """List current user's favorited events."""
    favs = Favorite.query.filter_by(user_id=current_user.id).all()
    events = [f.event for f in favs if f.event]
    return render_template('my_favorites.html', events=events)
