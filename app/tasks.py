
import atexit
from app.extensions import scheduler, db
from app.models import Check
from app.checks.runner import run_check


def initialize_scheduler(app):
    """Initialize and configure the APScheduler."""
    if not scheduler.running:
        scheduler.configure(
            jobstores={
                'default': {
                    'type': 'memory'
                }
            },
            executors={
                'default': {
                    'type': 'threadpool',
                    'max_workers': 20
                }
            },
            job_defaults={
                'coalesce': False,
                'max_instances': 3
            }
        )
        
        scheduler.start()
        atexit.register(lambda: scheduler.shutdown())


def schedule_health_checks():
    """Schedule all active health checks."""
    checks = Check.query.all()
    
    for check in checks:
        job_id = f"health_check_{check.id}"
        
        # Remove existing job if it exists
        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)
        
        # Add new job
        scheduler.add_job(
            func=execute_health_check,
            trigger="interval",
            seconds=check.interval_sec,
            id=job_id,
            args=[check.id],
            replace_existing=True
        )


def execute_health_check(check_id):
    """Execute a single health check and save the result."""
    from app import create_app
    
    # Create application context for database operations
    app = create_app()
    with app.app_context():
        check = Check.query.get(check_id)
        if not check:
            return
        
        try:
            result = run_check(check)
            db.session.add(result)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error executing health check for {check.name}: {str(e)}")


def add_or_update_check_job(check):
    """Add or update a scheduled job for a specific check."""
    job_id = f"health_check_{check.id}"
    
    # Remove existing job if it exists
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    
    # Add new job
    scheduler.add_job(
        func=execute_health_check,
        trigger="interval",
        seconds=check.interval_sec,
        id=job_id,
        args=[check.id],
        replace_existing=True
    )


def remove_check_job(check_id):
    """Remove a scheduled job for a specific check."""
    job_id = f"health_check_{check_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
