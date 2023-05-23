import sys

from django.conf import settings
from django.db import connection
from django.db.models import Q
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from fyxt.utils import error_logger
from inbox.models import Contact, Email, Phone
from .models import User, UserSetting
from .tasks import sync_hubspot_contact, default_dashboard_views, sync_keycloak


@receiver(pre_save, sender=User)
def user_old_value(sender, instance, **kwargs):
    # TODO need to refine this code block
    try:
        old_email = None
        if instance.id:
            if val := instance.__class__.objects.filter(pk=instance.id).first():
                old_email = val
        else:
            if connection.schema_name != 'public':
                contact = Contact.objects.get(Q(email=instance.email) | Q(email=old_email))
                contact.first_name = instance.first_name
                contact.last_name = instance.last_name
                contact.phone = instance.phone
                contact.user = instance
                contact.save()
    except Exception as e:
        error_logger(e, sys.exc_info())


@receiver(post_save, sender=User)
def user_post_save(sender, instance, created, **kwargs):
    # TODO need to refine this code block
    UserSetting.objects.get_or_create(user=instance)
    if connection.schema_name != 'public':
        try:
            if instance.email is not None:
                contact = Contact.objects.get(email=instance.email)
                contact.first_name = instance.first_name
                contact.last_name = instance.last_name
                contact.phone = instance.phone
                contact.user = instance
                contact.save()
        except Contact.DoesNotExist:
            contact = Contact.objects.create(
                email=instance.email,
                user=instance,
                first_name=instance.first_name,
                last_name=instance.last_name,
                phone=instance.phone
            )
            Email.objects.create(email=instance.email, contact=contact)
            Phone.objects.create(phone=instance.phone, contact=contact)

    if settings.SYNC_HUBSPOT_CONTACT:
        sync_hubspot_contact.delay(instance.id, created)

    '''This method creates a Dashboard View for the newly onboarded user(Manager, Engineer, and Tenant) 
    from Django or Email'''
    if instance.category in ['Customer', 'Tenant', 'Fyxt', 'Owner Group']:
        default_dashboard_views.apply_async(kwargs={'id': instance.id})


@receiver(post_save, sender=User)
def sync_user_in_keycloak(sender, instance, created, **kwargs):
    """
    This signal is used to sync user with Keycloak user on each save.
    """
    if created:
        payload = {
            'pk': instance.pk, 
            'email': instance.email, 
            'first_name': instance.first_name, 
            'last_name': instance.last_name, 
            'password': instance.password
        }
        sync_keycloak.delay(payload)
    else:
        #  TODO need to add flow for update user for password reset/ other user update flow
        pass
