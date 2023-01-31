from celery import shared_task
from django.contrib.auth import get_user_model
from django.core.mail import send_mail

@shared_task(bind=True)
def test_func(self):
    users = get_user_model().objects.all()
    for user in users:
     return "Done"
