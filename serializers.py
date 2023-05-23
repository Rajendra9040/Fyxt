import json

import requests
from django.conf import settings
from django.contrib.auth import password_validation
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.db.models import Q
from django.utils.timezone import now
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers

from customer.models import Engineer
from customer.tasks import user_status_upadte
from django_keycloak.models import Realm
from django_keycloak.models import Server
from fyxt.utils import has_valid_domain_access, get_user_by_email, validators, apply_new_dashboard_job_filter, \
    dashboard_columns_key_mapping
from job.models import Job
from .models import Country, State, City, Category, Company, CompanyAddress, PermissionLabel, Group, User, \
    EmailVerification, UserSetting, UserView, UserColumn, BaseColumn, Mailbox, CompanyContactType
from .tasks import send_forgot_password_link, health_checker


class CountrySerializer(serializers.ModelSerializer):
    """Serializer for Country details"""

    class Meta:
        """docstring for Meta"""
        model = Country
        fields = ('id', 'name')


class StateSerializer(serializers.ModelSerializer):
    """Serializer for State details"""

    class Meta:
        """docstring for Meta"""
        model = State
        fields = ('id', 'name')

    def to_representation(self, instance):
        data = super(StateSerializer, self).to_representation(instance=instance)
        data['name'] = data['name'].title()
        return data


class CitySerializer(serializers.ModelSerializer):
    """Serializer for City details"""
    state = serializers.CharField(label=_('Tenant'), source='state.name', allow_null=True)

    class Meta:
        """docstring for Meta"""
        model = City
        fields = ('id', 'name', 'state')

    def to_representation(self, instance):
        data = super(CitySerializer, self).to_representation(instance=instance)
        data['name'] = data['name'].title()
        return data


class CategorySerializer(serializers.ModelSerializer):
    """Serializer for Country details"""

    class Meta:
        """docstring for Meta"""
        model = Category
        fields = ('id', 'name')


class CompanyAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyAddress
        fields = ('id', 'address', 'country', 'state', 'city', 'zipcode')

    def update(self, instance, validated_data):
        instance.modified_by = self.context.get('request').user
        return super().update(instance, validated_data)


class CompanySerializer(serializers.ModelSerializer):
    address = CompanyAddressSerializer(label=_('Address'), required=False)

    class Meta:
        model = Company
        fields = ('id', 'name', 'entity_name', 'type', 'ein', 'address', 'is_active')

    def validate_ein(self, ein):
        if not ein and not ein.isspace():
            raise serializers.ValidationError(_('Space is not allowed'))
        return ein

    def update(self, instance, validated_data):
        if self.context.get('request').user.is_authenticated:
            instance.modified_by = self.context.get('request').user
        return super().update(instance, validated_data)


class CheckEmailSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email',)


class CheckPhoneSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('phone',)


class ValidateTokenSerializer(serializers.Serializer):
    token = serializers.UUIDField(label=_('Token'))

    def validate_token(self, token):
        queryset = EmailVerification.objects.filter(token=token, is_verified=False)
        if not queryset.exists():
            raise serializers.ValidationError(_('Token expired/Invalid'), code='authorization')

        return token


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(label=_('Email'), allow_blank=False)
    password = serializers.CharField(
        label=_('Password'),
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def authenticate(self, **kwargs):
        # user = get_user_by_email(kwargs.get('email'))
        email = kwargs.get('email')
        password = kwargs.get('password')
        server = Server.objects.first()
        realm = Realm.objects.first()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {
            "client_id": realm.client.client_id,
            "client_secret": realm.client.secret,
            "username": email,
            "password": password,
            "grant_type": "password"
        }

        url = f'{server.url}auth/realms/{realm.name}/protocol/openid-connect/token'
        response = requests.post(url, data=data, headers=headers)
        response_data = json.loads(response.text)
        if response.status_code != 200:
            return None
        user = User.objects.get(email=email)
        user.access_token = response_data.get('access_token', '')
        return user

        # return authenticate(self.context['request'], **kwargs)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            user = self.authenticate(email=email, password=password)

            if not user:
                raise serializers.ValidationError({'error': _('Unable to login with provided credentials.')},
                                                  code='authorization')

            try:
                if not user.email_verification.is_verified:
                    raise serializers.ValidationError({'error': _('Your account is not verified yet.')},
                                                      code='authorization')
            except ObjectDoesNotExist:
                raise serializers.ValidationError(
                    {'error': _('Your account is not verified yet.')},
                    code='authorization',
                )

            if user.is_suspended:
                raise serializers.ValidationError(
                    {'error': _('User account is suspended. Contact your administrator.')}, code='authorization')

            if not has_valid_domain_access(self.context.get('request'), user):
                raise serializers.ValidationError(
                    {'error': _('You do not have a valid domain access. Please contact your account admin.')},
                    code='authorization')

            if settings.ENVIRONMENT != 'LOCAL':
                user.last_login = now()
                user.save()

            return user


class PasswordResetSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset e-mail.
    """
    email = serializers.EmailField()

    def validate_email(self, email):
        self.user = get_user_by_email(email, is_active=True)
        if not self.user:
            raise serializers.ValidationError(_('The email is not assigned to any user account'))

        return email

    def save(self):
        send_forgot_password_link.delay(self.user.pk)
        return self.user.email


class GroupSerializer(serializers.ModelSerializer):
    permissions = serializers.StringRelatedField(many=True, read_only=True)
    users = serializers.SerializerMethodField(label=_('Users'))

    class Meta:
        model = Group
        fields = ('id', 'name', 'can_view', 'can_add', 'can_approve', 'can_added_job', 'permissions', 'users')

    def validate_name(self, name):
        validators.unique_together(
            queryset=Group.objects.filter(name__iexact=name, account=self.context.get('request').tenant,
                                          is_active=True),
            instance=self.instance,
            message=_('Sorry, the name which you have given is exist already!')
        )
        return name

    def validate(self, attrs):
        if not (attrs.get('can_view') or attrs.get('can_add') or attrs.get('can_approve') or attrs.get(
                'can_added_job')):
            raise serializers.ValidationError({'error': "You have to select at least one permission to this Role."})
        return attrs

    def create(self, validated_data):
        request = self.context.get('request')

        validated_data['created_by'] = request.user
        validated_data['account'] = request.tenant

        validated_data['permissions'] = self.get_permissions(validated_data)

        return super().create(validated_data)

    def update(self, instance, validated_data):
        instance.modified_by = self.context.get('request').user
        validated_data['permissions'] = self.get_permissions(validated_data)

        if 'Follower' not in validated_data['can_added_job']:
            for x in instance.users.all():
                for follower in x.followers.all():
                    follower.followers.remove(x.id)
        return super().update(instance, validated_data)

    def get_permissions(self, validated_data):
        values = []
        if validated_data.get('can_add'):
            for val in validated_data.get('can_add'):
                values.extend(
                    PermissionLabel.objects.filter(is_active=True, type='Add', name=val).values_list('permission',
                                                                                                     flat=True))
                values.extend(
                    PermissionLabel.objects.filter(is_active=True, type='Change', name=val).values_list('permission',
                                                                                                        flat=True))

        if validated_data.get('can_view'):
            for val in validated_data.get('can_view'):
                values.extend(
                    PermissionLabel.objects.filter(is_active=True, type='View', name=val).values_list('permission',
                                                                                                      flat=True))

        if validated_data.get('can_approve'):
            for val in validated_data.get('can_approve'):
                values.extend(
                    PermissionLabel.objects.filter(is_active=True, type='Approve', name=val).values_list('permission',
                                                                                                         flat=True))

        if validated_data.get('can_added_job'):
            for val in validated_data.get('can_added_job'):
                values.extend(
                    PermissionLabel.objects.filter(is_active=True, type='Added_Job', name=val).values_list('permission',
                                                                                                           flat=True))

        if values:
            return Permission.objects.filter(codename__in=values).values_list('id', flat=True)

        return []

    def get_users(self, obj):
        return [{'first_name': user.first_name, 'last_name': user.last_name} for user in
                obj.users.filter(is_active=True, is_suspended=False)]


class OnboardSerializer(serializers.ModelSerializer):
    token = serializers.UUIDField(label=_('Token'))
    password = serializers.CharField(label=_('Password'), max_length=128, write_only=True,
                                     style={'input_type': 'password'})
    last_name = serializers.CharField(label=_('Last Name'), max_length=255)
    recovery_email = serializers.EmailField(label=_('Recovery Email'))

    class Meta:
        model = User
        fields = ('token', 'first_name', 'last_name', 'recovery_email', 'phone', 'password')

    def validate_password(self, password):
        try:
            password_validation.validate_password(password)
        except ValidationError as errors:
            raise serializers.ValidationError(errors)

        return password

    def update(self, instance, validated_data):
        validated_data.pop('token')

        instance.modified_by = instance
        instance.is_active = True
        instance.set_password(validated_data.pop('password'))

        EmailVerification.objects.filter(user=instance).update(is_verified=True, modified_by=instance)

        if instance.category == 'Tenant':
            tenant = instance.tenant_member.tenant
            tenant.is_active = True
            tenant.save()
            # Todo need to replace value while DEV to QA (https://cc.docker.devapifyxt.com/ to self.context.get('request').url)
            user_status_upadte.delay(instance.id, 'https://cc.docker.devapifyxt.com/')
        elif instance.category == 'Vendor':
            vendor = instance.vendor_member.vendor
            vendor.is_active = True
            vendor.save()

        return super().update(instance, validated_data)


class UserShortSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email', 'phone')


class UserShortSearchSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'category', 'photo')


class MentionDropDownSerializer(serializers.ModelSerializer):
    value = serializers.SerializerMethodField(label=_('User Full Name'))

    class Meta:
        model = User
        fields = ('id', 'value', 'types')

    def get_value(self, obj):
        return obj.full_name


class UserDropDownSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('id', 'full_name', 'types')


class UserShortListSerializer(serializers.ModelSerializer):
    phone = serializers.SerializerMethodField(label=_('Phone'))

    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email', 'phone')

    def get_phone(self, obj):
        return obj.phone_dict


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'accounts', 'category', 'types', 'email', 'recovery_email', 'phone', 'first_name', 'last_name',
                  'gender', 'photo', 'popup', 'is_first_ticket_created', 'is_first_time_login', 'live', 'notes',
                  'is_suspended', 'is_active')

    def update(self, instance, validated_data):
        instance.modified_by = self.context.get('request').user
        if validated_data.get('photo'):
            instance.photo.delete(False)
        return super().update(instance, validated_data)


class ChangePasswordSerializer(serializers.ModelSerializer):
    """
    Serializer for password change endpoint.
    """
    # current_password = serializers.CharField(label='Current Password', write_only=True,
    #                                          style={'input_type': 'password'})
    new_password = serializers.CharField(label='New Password', write_only=True, style={'input_type': 'password'})
    confirm_new_password = serializers.CharField(label='Confirm New Password', write_only=True,
                                                 style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ('new_password', 'confirm_new_password')

    def validate(self, data):
        if data.get('new_password') != data.get('confirm_new_password'):
            raise serializers.ValidationError({'confirm_new_password': "Those passwords don't match."})

        try:
            password_validation.validate_password(data.get('confirm_new_password'))
        except ValidationError as errors:
            raise serializers.ValidationError({'confirm_new_password': errors})

        return data

    def update(self, instance, validated_data):
        instance.set_password(validated_data['confirm_new_password'])
        instance.modified_by = instance
        instance.save()

        return instance


class UserSettingSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSetting
        fields = ('id', 'user', 'email_notification_for_new_jobs', 'email_notification_for_job_updates',
                  'email_notification_for_new_messages',
                  'email_notification_for_high_priority_job_over_due_by_two_days',
                  'email_notification_for_job_overdue_by_one_week', 'email_notification_for_emergency_job_created',
                  'sms_notification_for_new_jobs', 'sms_notification_for_job_updates',
                  'sms_notification_for_new_messages',
                  'sms_notification_for_high_priority_job_over_due_by_two_days',
                  'sms_notification_for_job_overdue_by_one_week', 'sms_notification_for_emergency_job_created',
                  'push_notification_for_new_jobs', 'push_notification_for_job_updates',
                  'push_notification_for_new_messages', 'push_notification_for_high_priority_job_over_due_by_two_days',
                  'push_notification_for_job_overdue_by_one_week', 'push_notification_for_emergency_job_created')

    def update(self, instance, validated_data):
        instance.modified_by = self.context.get('user')
        return super().update(instance, validated_data)


class UserViewsSerializer(serializers.ModelSerializer):
    column = serializers.SerializerMethodField(label=_('User Column'))
    count = serializers.SerializerMethodField(label=_('Count'))
    is_edit = serializers.SerializerMethodField(label=_('Permission To Edit Column'))
    reset = serializers.BooleanField(label=_('Reset'), required=False, write_only=True)

    class Meta:
        model = UserView
        fields = (
            'id', 'view_name', 'make_as_default', 'is_private', 'is_pin', 'is_edit', 'query', 'count', 'column',
            'reset', 'current_active_tab')

    def get_column(self, obj):
        data = []
        for column in UserColumn.objects.filter(view=obj, is_select=True):
            if column.column_name == "Actions":
                data.extend([{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "actions",
                              'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Assigned Engineers":
                data.extend(
                    [{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "engineers",
                      'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Assigned Managers":
                data.extend([{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "managers",
                              'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Assigned To":
                data.extend(
                    [{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "assigned_to",
                      'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Associated Emails":
                data.extend(
                    [{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "associated_email",
                      'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Billable Party":
                data.extend(
                    [{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "billable_party",
                      'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Brief Description":
                data.extend(
                    [{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "issue_type",
                      'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Category":
                data.extend([{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "category",
                              'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Date Created":
                data.extend(
                    [{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "created_at",
                      'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Followers":
                data.extend(
                    [{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "followers",
                      'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Job ID":
                data.extend([{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "id",
                              'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Last Activity":
                data.extend(
                    [{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "modified_at",
                      'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Linked Jobs":
                data.extend(
                    [{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "linked_jobs",
                      'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Priority":
                data.extend([{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "priority",
                              'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Property":
                data.extend([{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "property",
                              'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Service Location":
                data.extend([{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "location",
                              'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Service Type":
                data.extend(
                    [{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "service_type",
                      'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Source Type":
                data.extend([{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "source",
                              'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Status":
                data.extend([{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "stage",
                              'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Target Completion Date":
                data.extend(
                    [{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "target_date",
                      'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Tenant Contact":
                data.extend(
                    [{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "tenant_contact",
                      'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Tenant":
                data.extend([{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "tenant",
                              'width': column.custom.get('width', '') if column.custom else ''}])

            elif column.column_name == "Vendor(s)":
                data.extend([{'id': column.id, 'order': column.order, 'name': column.column_name, 'value': "vendors",
                              'width': column.custom.get('width', '') if column.custom else ''}])

        return data

    def get_count(self, obj):
        user = self.context.get('user')
        if user.category == 'Customer':
            if 'Owner' in user.types:
                queryset = Job.objects.select_related('category', 'property', 'tenant__company').filter(is_active=True)
            elif 'Manager' in user.types:
                queryset = Job.objects.select_related('category', 'property', 'tenant__company').filter(is_active=True,
                                                                                                        property__managers__user=user)
            elif 'Engineer' in user.types:
                if Engineer.objects.filter(user_id=user.id, primary_contact=True):
                    queryset = Job.objects.select_related('category', 'property', 'tenant__company').filter(
                        property__engineers__user=user, is_active=True).distinct()
                else:
                    queryset = Job.objects.select_related('category', 'property', 'tenant__company').filter(
                        Q(engineers=user) | Q(created_by=user), is_active=True).distinct()
        elif user.category == 'Tenant':
            queryset = Job.objects.select_related('category', 'property', 'tenant__company').filter(is_active=True,
                                                                                                    tenant__company=user.tenant_member.tenant.company)

        if obj.view_name not in ['Assigned To Me', 'Unassigned', 'New Requests', 'Tenant Responsible', 'Requires Attention', 'My Properties']:
            return apply_new_dashboard_job_filter(queryset, _filter='All Open Jobs', user=user).count()
        else:
            return apply_new_dashboard_job_filter(queryset, _filter=obj.view_name, user=user).count()

    def get_is_edit(self, obj):
        user = self.context.get('user')
        return False if obj.created_by is None and obj.is_private is False or obj.user != user else True

    def validate_is_pin(self, is_pin):
        user = self.context.get('user')
        user_view = UserView.objects.filter(id=self.instance.id, created_by__isnull=False, is_private=False)

        if is_pin is True and UserView.objects.filter(user=user, is_pin=True).count() >= 5:
            raise serializers.ValidationError(_(f'You can\'t pin more than 5 views'))

        if user_view and is_pin is True and user_view[0].created_by != user:
            raise serializers.ValidationError(
                _(f'You can\'t pin others\' template views. Save as new to pin a view.'))

        return is_pin

    def validate_view_name(self, view_name):
        user = self.context.get('user')

        if UserView.objects.filter(user=user, view_name=view_name):
            raise serializers.ValidationError(_(f'"{view_name}" is already exists!'))

        return view_name

    def create(self, validated_data):
        user = self.context.get('user')
        validated_data['created_by'] = user
        validated_data['user'] = user

        column_list = ['Job ID', 'Last Activity', 'Property', 'Brief Description', 'Category', 'Priority', 'Actions',
                       'Service Location', 'Assigned Managers', 'Assigned Engineers', 'Date Created', 'Status',
                       'Service Type', 'Linked Jobs', 'Source Type']

        if lists := self.context.get('columns', None):
            view = super().create(validated_data)
            for column in BaseColumn.objects.all():
                if column.column_name in lists:
                    UserColumn.objects.create(view=view, order=lists.index(column.column_name) + 1,
                                              column_name=column.column_name, is_select=True)
                else:
                    UserColumn.objects.create(view=view, order=0, column_name=column.column_name)
            return view

        view = super().create(validated_data)

        # Add a default columns to this view
        for column in BaseColumn.objects.all():
            if column.column_name in column_list:
                UserColumn.objects.create(view=view, order=column_list.index(column.column_name) + 1,
                                          column_name=column.column_name, is_select=True)
            else:
                UserColumn.objects.create(view=view, order=0, column_name=column.column_name)

        return view

    def update(self, instance, validated_data):
        user = self.context.get('user')
        instance.modified_by = user

        queryset = UserView.objects.filter(user=user)
        if validated_data.get('is_pin') is True and queryset.filter(is_pin=True).count() == 0:
            instance.make_as_default = True
            self._extracted_from_update(queryset, user)
        if validated_data.get('make_as_default') is True:
            self._extracted_from_update(queryset, user)
        if validated_data.get('current_active_tab') is True:
            queryset.update(current_active_tab=False)
            instance.current_active_tab = True
            instance.modified_by = user

        if validated_data.get('query'):
            instance.query = validated_data.get('query')

        if validated_data.get('reset'):
            if rest := validated_data.pop('reset'):
                if rest is True:
                    instance.query = None

        return super().update(instance, validated_data)

    def _extracted_from_update(self, queryset, user):
        view = queryset.get(make_as_default=True)
        view.make_as_default = False
        view.modified_by = user
        view.save()


class UserColumnsSerializer(serializers.ModelSerializer):
    value = serializers.SerializerMethodField(label=_('User Column'))

    class Meta:
        model = UserColumn
        fields = ('id', 'order', 'column_name', 'is_select', 'value')

    def get_value(self, obj):
        return dashboard_columns_key_mapping(obj)

    def update(self, instance, validated_data):
        instance.modified_by = self.context.get('user')
        return super().update(instance, validated_data)


# Version 2 Dashboard view
class UserDashboardViewSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserView
        fields = (
            'id', 'view_name', 'make_as_default', 'is_private', 'is_pin', 'query',
            'current_active_tab', 'is_standard', 'view_type')

    def validate_view_name(self, view_name):
        user = self.context.get('user')

        if UserView.objects.filter(user=user, view_name=view_name):
            raise serializers.ValidationError(_(f'"{view_name}" is already exists!'))

        return view_name

    def create(self, validated_data):
        user = self.context.get('user')
        validated_data['created_by'] = user
        validated_data['user'] = user

        column_list = ['Job ID', 'Last Activity', 'Property', 'Brief Description', 'Category', 'Priority', 'Actions',
                       'Service Location', 'Assigned Managers', 'Assigned Engineers', 'Date Created', 'Status',
                       'Service Type', 'Linked Jobs', 'Source Type']

        if lists := self.context.get('columns', None):
            view = super().create(validated_data)
            for column in BaseColumn.objects.all():
                if column.column_name in lists:
                    UserColumn.objects.create(view=view, order=lists.index(column.column_name) + 1,
                                              column_name=column.column_name, is_select=True)
                else:
                    UserColumn.objects.create(view=view, order=0, column_name=column.column_name)
            return view

        view = super().create(validated_data)

        # Add a default columns to this view
        for column in BaseColumn.objects.all():
            if column.column_name in column_list:
                UserColumn.objects.create(view=view, order=column_list.index(column.column_name) + 1,
                                          column_name=column.column_name, is_select=True)
            else:
                UserColumn.objects.create(view=view, order=0, column_name=column.column_name)

        return view

    def update(self, instance, validated_data):
        user = self.context.get('user')
        instance.modified_by = user

        queryset = UserView.objects.filter(user=user)

        if validated_data.get('is_pin') is False and instance.make_as_default is True:
            instance.make_as_default = False
            view = queryset.get(view_name='All Open Jobs')
            view.make_as_default = True
            view.modified_by = user
            view.save()

        if validated_data.get('make_as_default') is True:
            queryset.update(make_as_default=False)
            instance.make_as_default = True
            instance.is_pin = True
            instance.modified_by = user

        if validated_data.get('current_active_tab') is True:
            queryset.update(current_active_tab=False)
            instance.current_active_tab = True
            instance.modified_by = user

        if validated_data.get('query'):
            instance.query = validated_data.get('query')

        return super().update(instance, validated_data)


class UserDashboardViewColumnsSerializer(serializers.ModelSerializer):
    name = serializers.CharField(label=_('Column Name'), source='column_name')
    checked = serializers.SerializerMethodField(label=_('Created By'))
    class Meta:
        model = UserColumn
        fields = ('id', 'order', 'name', 'checked')

    def get_checked(self, obj):
        return obj.is_select


class HealthSerializer(serializers.Serializer):
    health = serializers.CharField(label=_('health'))

    def create(self, validated_data):
        health_ratio = health_checker(health=validated_data.pop('health'))
        return {"health": str(health_ratio)}


class MailboxSerializer(serializers.ModelSerializer):
    """Serializer for Mailbox details"""
    created_by = serializers.SerializerMethodField(label=_('Created By'))

    class Meta:
        """docstring for Meta"""
        model = Mailbox
        fields = (
        'id', 'name', 'preferred_tz', 'host', 'email', 'password', 'port', 'use_tls', 'primary', 'type', 'redirect_url', 'created_by')
        extra_kwargs = {'account': {'write_only': True}, 'password': {'write_only': True},
                        'port': {'write_only': True}, 'use_tls': {'write_only': True},
                        'primary': {'write_only': True}, 'type': {'write_only': True},
                        'host': {'write_only': True}, 'redirect_url': {'write_only': True}, }

    def create(self, validated_data):
        request = self.context.get('request')
        validated_data['created_by'] = request.user
        validated_data['account'] = request.tenant
        return super().create(validated_data)

    def get_created_by(self, obj):
        return obj.created_by.short_profile_dict() if obj.created_by else None


class CompanyContactTypeSerializer(serializers.ModelSerializer):
    """Serializer for Company Contact Types details"""
    class Meta:
        """docstring for Meta"""
        model = CompanyContactType
        fields = ('id', 'name')
    def to_representation(self, instance):
        data = super(CompanyContactTypeSerializer, self).to_representation(instance=instance)
        # data['name'] = data['name'].title()
        return data
