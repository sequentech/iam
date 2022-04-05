import os

from celery import Celery
from celery.utils.log import get_task_logger
from celery.signals import beat_init
from django.conf import settings

logger = get_task_logger(__name__)

@beat_init.connect
def reset_tallies_task(sender=None, conf=None, **kwargs):
    '''
    Resets the status of the all the AuthEvents with tally pending or started
    to notstarted.
    '''
    logger.info(
        'reset_tallies_task: resetting the status of any all the AuthEvents ' +
        'with tally pending or started to notstarted'
    )
    from api.models import AuthEvent
    AuthEvent\
        .objects\
        .filter(tally_status__in=[
            AuthEvent.PENDING,
            AuthEvent.STARTED
        ])\
        .update(tally_status=AuthEvent.NOT_STARTED)

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'iam.settings')

app = Celery('iam')

app.config_from_object(settings.CELERY_CONFIG)

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()


@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
