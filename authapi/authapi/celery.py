import os

from celery import Celery
from celery.signals import celeryd_init
from django.conf import settings

@celeryd_init.connect
def reset_tallies_task(sender=None, conf=None, **kwargs):
    '''
    Resets the status of the all the AuthEvents with tally pending or started
    to notstarted.
    '''
    print('resetting the status of any all the AuthEvents with tally ' +
          'pending or started to notstarted')
    from api.models import AuthEvent
    AuthEvent\
        .objects\
        .filter(tally_status__in=['pending','started'])\
        .update(tally_status='notstarted')

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'authapi.settings')

app = Celery('authapi')

app.config_from_object(settings.CELERY_CONFIG)

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()


@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
