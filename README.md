# Tech Access Platform

A Flask-based web application for managing events, RSVPs, user profiles, and company listings, designed to support accessible technology communities. Companies can create events, upload images, categorize them, and track attendee sign-ups, while users can search, RSVP, and manage their profiles.

## Features

* **User Authentication**: Register, login, and logout functionality via `Flask-Login`.
* **User Profiles**: View and edit personal information and upload profile avatars.
* **Event Management**:

  * Create, edit, and view events with title, description, date, image, and category.
  * Only authenticated company users can create or modify events and upload event images.
* **RSVP System**:

  * RSVP to events and cancel RSVPs.
  * “My RSVPs” page displays all events a user has signed up for.
* **Search**:

  * Event search by title or description (`/search`).
  * Company search by name or description (`/search/companies`).
* **Event Categories**: Assign and filter events by categories. Admins or company users can manage categories.
* **Attendee List & Popularity**:

  * View a list of attendees for each event.
  * Display RSVP counts (popularity) on event listings and detail pages.
* **Testing**: Comprehensive pytest suite covering authentication, profiles, events, RSVPs, search, image uploads, and categories.

## Technology Stack

* **Backend**: Python 3, Flask, Flask-SQLAlchemy, Flask-Migrate, Flask-Login, Flask-WTF
* **Database**: SQLite (development) / PostgreSQL (production)
* **Templating**: Jinja2, Bootstrap 5
* **Testing**: pytest

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/lancepounds/tech-access-platform.git
   cd tech-access-platform
   ```
2. **Install dependencies**:

   * Using pip:

     ```bash
     python3 -m venv venv
     source venv/bin/activate
     pip install -r requirements.txt
     ```
   * Or using Poetry:

     ```bash
     poetry install
     ```
3. **Configure environment variables**:
   Create a `.env` file in the project root with:

   ```ini
   FLASK_APP=app
   FLASK_ENV=development
   SECRET_KEY=your-secret-key
   DATABASE_URL=sqlite:///app.db  # or your PostgreSQL URI
   ```
4. **Run database migrations**:

   ```bash
   flask db upgrade
   ```

## Running the Application

Start the development server:

```bash
flask run
```

Visit `http://localhost:5000` in your browser.

## Directory Structure

```
tech-access-platform/
├── app/                   # Application package
│   ├── __init__.py        # Application factory
│   ├── models.py          # SQLAlchemy models
│   ├── main.py            # Event and search routes
│   ├── users.py           # Authentication and profile routes
│   ├── categories.py      # Category management routes
│   ├── extensions.py      # Flask extensions (db, login_manager)
│   ├── templates/         # Jinja2 templates
│   └── static/            # Static files (CSS, JS, uploads)
├── tests/                 # pytest test modules
├── migrations/            # Alembic migration scripts
├── config.py              # Application configuration
├── requirements.txt       # pip dependencies
├── pyproject.toml         # Poetry configuration
└── README.md              # Project documentation
```

## Running Tests

Execute the full test suite with:

```bash
pytest
```

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/YourFeature`.
3. Commit your changes: `git commit -m "Add new feature"`.
4. Push to your fork: `git push origin feature/YourFeature`.
5. Open a pull request for review.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
