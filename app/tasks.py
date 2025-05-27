
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
        
        # Schedule the poll_all_checks job to run every minute
        schedule_poll_all_checks()


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


def poll_all_checks():
    """Poll all active checks and save results to database."""
    from app import create_app
    
    # Create application context for database operations
    app = create_app()
    with app.app_context():
        try:
            # Query all active Check records
            checks = Check.query.all()
            
            for check in checks:
                try:
                    # Run the check and get result
                    result = run_check(check)
                    
                    # Add and commit the result to database
                    db.session.add(result)
                    db.session.commit()
                    
                except Exception as e:
                    # Rollback this specific check's transaction
                    db.session.rollback()
                    print(f"Error polling check {check.name} (ID: {check.id}): {str(e)}")
                    
        except Exception as e:
            print(f"Error in poll_all_checks: {str(e)}")


def schedule_poll_all_checks():
    """Schedule the poll_all_checks function to run every minute."""
    job_id = "poll_all_checks"
    
    # Remove existing job if it exists
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    
    # Add job to run every minute
    scheduler.add_job(
        func=poll_all_checks,
        trigger="interval",
        seconds=60,  # Run every minute
        id=job_id,
        replace_existing=True
    )
