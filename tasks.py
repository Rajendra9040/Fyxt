import sys
import time

import sentry_sdk
from celery import shared_task

from django.core import management
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator as token_generator
from django.db import connection
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django_tenants.utils import schema_context

from account.models import BaseView, UserView, UserColumn, AccountsNotificationSetUp, Domain
from customer.models import Category
from fyxt.celery import app
from fyxt.utils import error_logger, build_hubspot_context, can_notify, info_logger
from fyxt.utils.crm import HubSpot, Dynamics
from fyxt.utils.sms import SMS
from fyxt.utils.keycloak import Keycloak
from .models import Account, User, EmailVerification

hubspot = HubSpot()


@app.task
def send_welcome_email(user_id, sender_id=None, origin=settings.ROOT_ORIGIN):
    try:
        user = User.objects.get(pk=user_id)
        obj, created = EmailVerification.objects.get_or_create(user=user)

        hubspot_context = build_hubspot_context(user)
        context = {
            "customProperties": [
                {
                    "name": "subject",
                    "value": "Welcome to FYXT!"
                },
                {
                    "name": "full_name",
                    "value": user.full_name
                },
                {
                    "name": "link",
                    "value": f'{origin}/onboard/{obj.token}/{user.category.lower()}/'
                }

            ]
        }
        hubspot_context.update(context)

        if user.category == 'Customer' and 'Engineer' not in user.types:
            hubspot_context.update({'emailId': 43240504661})
            hubspot_context["customProperties"].append({"name": "properties", "value": ', '.join(
                [manager.property.name for manager in user.managers.filter(is_active=True)])})

        elif 'Engineer' in user.types:
            hubspot_context.update({'emailId': 50976051232})
            hubspot_context["customProperties"].append({"name": "properties", "value": ', '.join(
                [engineer.property.name for engineer in user.engineers.filter(is_active=True)])})

        elif user.category == 'Vendor':
            sender = User.objects.get(id=sender_id)
            hubspot_context.update({'emailId': 43240504891})
            hubspot_context["customProperties"].append({"name": "properties", "value": ', '.join(
                [val.name for val in user.vendor_member.vendor.properties.all()])})
            hubspot_context["customProperties"].append({"name": "manager", "value": sender.full_name})

        elif user.category == 'Tenant':
            hubspot_context.update({'emailId': 43240298801})
            hubspot_context["customProperties"].append({"name": "properties", "value": ', '.join(
                [val.property.name for val in user.tenant_member.tenant.properties.filter(is_active=True)])})

        account = Domain.objects.get(origin=origin).tenant
        account_permission = AccountsNotificationSetUp.objects.get(account_id=account.id)
        if account_permission.user_invitation_email:
            hubspot.send_email(hubspot_context, source=f'account->tasks.py->send_welcome_email->User Category{user.category}')
    except Exception as e:
        error_logger(e, sys.exc_info())


# @app.task
# def send_forgot_password_link(pk):
#     user = User.objects.get(pk=pk)
#     link = f'{settings.ROOT_ORIGIN}/password/reset/confirm/{urlsafe_base64_encode(force_bytes(user.pk))}/{token_generator.make_token(user)}',
#     send(
#         template='password_reset.html',
#         subject='Password Reset Link',
#         receivers=user.email,
#         context={"link": link, "full_name": user.full_name,}
#         )


@app.task
def send_forgot_password_link(pk):
    user = User.objects.get(pk=pk)
    hubspot_context = build_hubspot_context(user)
    hubspot_context.update({
        'emailId': 43240400944,
        "customProperties": [
            {
                "name": "subject",
                "value": "Password Reset Link"
            },
            {
                "name": "full_name",
                "value": user.full_name
            },
            {
                "name": "link",
                "value": f'{settings.ROOT_ORIGIN}/password/reset/confirm/{urlsafe_base64_encode(force_bytes(pk))}/{token_generator.make_token(user)}',
            }
        ]
    })
    hubspot.send_email(hubspot_context, source='account->tasks.py->send_forgot_password_link')


@app.task
def send_sms(user, template, action):
    user = User.objects.get(pk=user)
    try:
        if user.phone and can_notify(user, action, channel='sms'):
            sms = SMS()
            phone = user.phone_dict
            sms.send(template=template, receiver=phone.get('e164_number'), country=phone.get('country_code'))
    except Exception as e:
        error_logger(e, sys.exc_info())

@app.task
def sync_hubspot_contact(user, created):
    try:
        time.sleep(10)
        user = User.objects.get(pk=user)
        hubspot.sync_contact(user, created)
    except Exception as e:
        sentry_sdk.set_tag("hubspot:user", user.full_name if user is not None else None)
        sentry_sdk.capture_exception(e)


@app.task
def sync_category(name, is_active=True, _id=None):
    for account in Account.objects.filter(is_active=True).exclude(schema_name='public'):
        with schema_context(account.schema_name):
            if _id:
                Category.objects.get_or_create(id=_id, name__iexact=name,
                                               defaults={'id': _id, 'name': name, 'is_active': is_active})
            else:
                Category.objects.get_or_create(name__iexact=name, defaults={'is_active': is_active})


@app.task
def sync_contact_dynamics(user, onscreen=False):
    user = User.objects.get(id=user)
    dyn = Dynamics()
    contact = None
    try:
        # contact = dyn.get('contacts', filters=f"?$filter=emailaddress1 eq '{user.email}' &$top=1")
        if user.crm_contact_id:
            try:
                contact = dyn.get('contacts', filters=f"?$filter=contactid eq '{user.crm_contact_id}' &$top=1")
            except:
                pass
        if not contact:
            try:
                contact = dyn.get('contacts', filters=f"?$filter=emailaddress1 eq '{user.email}' &$top=1")
                user.crm_contact_id = contact.get('contactid')
                user.save()
            except:
                pass
        if not contact:
            data = {
                'firstname': user.first_name,
                'lastname': user.last_name,
                'emailaddress1': user.email,
                'new_fyxtuser': True,
                'mobilephone': user.phone.as_international
            }

            if user.recovery_email and user.recovery_email != '':
                data.update({'emailaddress2': user.recovery_email})

            resp = dyn.create(entity='contacts', data=data)

            if resp.status_code == 201:
                json_resp = resp.json()
                user.crm_contact_id = json_resp.get('contactid')
                user.save()
                info_logger(f'sync_contact_dynamics() created user in CRM: {user.email}')
            else:
                error_logger(data)
                error_logger(resp.content)

        if contact and user.crm_contact_id:
            contact = contact[0]
            data = dict()

            if contact.get('firstname') != user.first_name:
                data.update({'firstname': user.first_name})

            if contact.get('lastname') != user.last_name:
                data.update({'lastname': user.last_name})

            if contact.get('emailaddress1') != user.email:
                data.update({'emailaddress1': user.email})

            if contact.get('mobilephone') != user.phone.as_international:
                data.update({'mobilephone': user.phone.as_international})

            if contact.get('emailaddress2') != user.recovery_email and user.recovery_email != '':
                data.update({'emailaddress2': user.recovery_email})

            if data:
                resp = dyn.update(entity='contacts', uid=contact.get('contactid'), data=data)

                if resp.status_code != 201:
                    error_logger(data)
                    error_logger(resp.content)

        elif contact and not user.crm_contact_id:
            user.crm_contact_id = contact[0].get('contactid')
            user.save()

    except Exception as e:
        error_logger(e, sys.exc_info())


@app.task
def health_checker(health):
    with connection.cursor() as cursor:
        try:
            cursor.execute(health)
            return cursor.fetchall()
        except:
            return health
        finally:
            cursor.close()


def crm_contact_id_checking_in_dynamics(user_id, onscreen=False):
    user = User.objects.get(id=user_id)
    dyn = Dynamics()
    contact = None
    try:
        # contact = dyn.get('contacts', filters=f"?$filter=emailaddress1 eq '{user.email}' &$top=1")
        if user.crm_contact_id:
            try:
                contact = dyn.get('contacts', filters=f"?$filter=contactid eq '{user.crm_contact_id}' &$top=1")
            except:
                pass
        if not contact:
            try:
                contact = dyn.get('contacts', filters=f"?$filter=emailaddress1 eq '{user.email}' &$top=1")
                user.crm_contact_id = contact.get('contactid')
                user.save()
            except:
                pass

        if contact:
            return True
        else:
            return False
    except Exception as e:
        error_logger(e, sys.exc_info())

@app.task
def default_dashboard_views(id):
    user = User.objects.get(id=id)
    try:
        columns = ['Job ID', 'Last Activity', 'Property', 'Brief Description', 'Category', 'Priority', 'Actions',
                   'Service Location', 'Assigned Managers', 'Assigned Engineers', 'Date Created', 'Status',
                   'Service Type', 'Linked Jobs', 'Source Type', 'Target Completion Date', 'Associated Emails',
                   'Vendor(s)', 'Followers', 'Tenant', 'Tenant Contact', 'Billable Party',
                   'Assigned To']

        selected = ['Job ID', 'Last Activity', 'Property', 'Brief Description', 'Category', 'Priority', 'Actions',
                    'Service Location', 'Assigned Managers', 'Assigned Engineers', 'Date Created', 'Status', 'Service Type',
                    'Linked Jobs', 'Source Type']

        for view in BaseView.objects.all():
            if not UserView.objects.filter(user=user, view_name=view):
                if view.view_name == 'All Open Jobs':
                    _view = UserView.objects.create(user=user, view_name=view.view_name, is_pin=True,
                                                    make_as_default=True, current_active_tab=True)
                    for col in columns:
                        if col in selected:
                            UserColumn.objects.create(view=_view, order=columns.index(col) + 1, column_name=col,
                                                      is_select=True)
                        else:
                            UserColumn.objects.create(view=_view, order=columns.index(col) + 1, column_name=col)
                    continue

                if view.view_name == 'Assigned To Me':
                    _view = UserView.objects.create(user=user, view_name=view.view_name, is_pin=True)
                    for col in columns:
                        if col in selected:
                            UserColumn.objects.create(view=_view, order=columns.index(col) + 1, column_name=col,
                                                      is_select=True)
                        else:
                            UserColumn.objects.create(view=_view, order=columns.index(col) + 1, column_name=col)
                    continue

                else:
                    _view = UserView.objects.create(user=user, view_name=view.view_name)
                    for col in columns:
                        if col in selected:
                            UserColumn.objects.create(view=_view, order=columns.index(col) + 1, column_name=col,
                                                      is_select=True)
                        else:
                            UserColumn.objects.create(view=_view, order=columns.index(col) + 1, column_name=col)
                    continue
        # Adding My properties view here only for engineer, not for all.
        if 'Engineer' in user.types:
            _view = UserView.objects.create(user=user, view_name="My Properties")
            for col in columns:
                if col in selected:
                    UserColumn.objects.create(view=_view, order=columns.index(col) + 1, column_name=col,
                                            is_select=True)
                else:
                    UserColumn.objects.create(view=_view, order=columns.index(col) + 1, column_name=col)

    except Exception as e:
        error_logger(e, sys.exc_info())

@app.task
def sync_keycloak(payload):
    try:
        keycloak = Keycloak()
        keycloak.add_user(**payload)
    except Exception as e:
        error_logger(e, sys.exc_info())

@shared_task
def hubspot_contact_sync():
    try:
        management.call_command("hubspot_contact_sync", verbosity=0)
        return "Success"
    except Exception as e:
        error_logger(e, sys.exc_info())
