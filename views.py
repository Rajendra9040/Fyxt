import json
import sys
from datetime import datetime

import requests
from dj_rest_auth.views import sensitive_post_parameters_m
from django.conf import settings
from django.db.models import Value, Q
from django.http import JsonResponse
from django.shortcuts import redirect
from django.utils.translation import ugettext_lazy as _
from django_tenants.utils import schema_context
from rest_framework import filters
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.decorators import api_view, permission_classes
from rest_framework.generics import GenericAPIView
from rest_framework.mixins import ListModelMixin, UpdateModelMixin
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet, ModelViewSet
from rest_framework_simplejwt.settings import api_settings as jwt_settings

from account.tasks import send_welcome_email
from customer.models import Engineer
from customer.models import Property, CompanyProperty
from customer.serializers import CompanyPropertyViewSetSerializer, CompanyJobViewSetSerializer
from fyxt.utils import error_logger
from fyxt.utils import get_domains, feature_flag_status, CustomSearchFilter, apply_new_dashboard_job_filter, ordering
from fyxt.utils.fyxt_cc import company_detail_tab_count, create_company
from fyxt.utils.mixins import SerializerClassMixin, ContextMixin
from fyxt.utils.pagination import CustomPagination
from fyxt.utils.permissions import has_permissions
from inbox.models import Contact
from inbox.outlook_provider import get_outlook_oauth_url, get_outlook_token
from job.models import Job
from tenant.models import TenantMember
from .models import (
    Country,
    State,
    City,
    Category,
    PermissionLabel,
    Group,
    User,
    EmailVerification,
    UserSetting,
    UserView,
    UserColumn,
    BaseView,
    Mailbox,
    Domain,
    Company,
    CompanyContactType
)
from .serializers import (
    CountrySerializer,
    StateSerializer,
    CitySerializer,
    CategorySerializer,
    CheckEmailSerializer,
    CheckPhoneSerializer,
    ValidateTokenSerializer,
    LoginSerializer,
    UserSerializer,
    ChangePasswordSerializer,
    GroupSerializer,
    UserSettingSerializer,
    UserViewsSerializer,
    UserColumnsSerializer,
    MailboxSerializer,
    HealthSerializer,
    CompanyContactTypeSerializer,
    UserDashboardViewSerializer,
    UserDashboardViewColumnsSerializer,
    UserDropDownSerializer,
    UserShortSearchSerializer
)


class CountryViewSet(GenericViewSet, ListModelMixin):
    serializer_class = CountrySerializer
    permission_classes = (AllowAny,)
    filter_backends = [filters.SearchFilter]
    search_fields = ['name']

    def get_queryset(self):
        with schema_context('public'):
            queryset = Country.objects.filter(is_active=True)
            name = self.request.query_params.get('name')
            if name is not None:
                queryset = queryset.filter(name__iexact=name)
            return queryset


class StateViewSet(GenericViewSet, ListModelMixin):
    serializer_class = StateSerializer
    permission_classes = (AllowAny,)
    pagination_class = None
    filter_backends = [filters.SearchFilter]
    search_fields = ['name', 'country__name']

    def get_queryset(self):
        with schema_context('public'):
            queryset = State.objects.filter(is_active=True).order_by('name').distinct('name')
            country = self.request.query_params.get('country')

            if country is not None:
                try:
                    queryset = queryset.filter(country__id=country)
                except:
                    queryset = queryset.filter(country__name__iexact=country)

            return queryset


class CityViewSet(GenericViewSet, ListModelMixin):
    serializer_class = CitySerializer
    permission_classes = (AllowAny,)
    pagination_class = None
    filter_backends = [filters.SearchFilter]
    search_fields = ['name', 'state__name']

    def get_queryset(self):
        with schema_context('public'):
            queryset = City.objects.select_related('state').filter(is_active=True).order_by('name').distinct('name')
            state = self.request.query_params.get('state')

            if state is not None:
                try:
                    queryset = queryset.filter(state__id=state)
                except:
                    queryset = queryset.filter(state__name__iexact=state)

            return queryset

    @action(detail=False, methods=['get'], url_path='dropdown')
    def dropdown(self, request, pk=None):
        self.pagination_class = CustomPagination
        self.filter_backends = [CustomSearchFilter]
        self.search_fields = ['name', 'state__name']
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)

        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class CategoryViewSet(GenericViewSet, ListModelMixin):
    serializer_class = CategorySerializer
    permission_classes = (AllowAny,)
    pagination_class = None

    def get_queryset(self):
        with schema_context('public'):
            queryset = Category.objects.filter(is_active=True).order_by('name')
            name = self.request.query_params.get('name')
            if name is not None:
                queryset = queryset.filter(name__iexact=name)
            return queryset


class CheckEmailView(GenericAPIView):
    serializer_class = CheckEmailSerializer
    permission_classes = (AllowAny,)

    def get(self, request, *args, **kwargs):
        return self.finalize_response(request, self.http_method_not_allowed(request, *args, **kwargs), *args, **kwargs)

    def post(self, request, *args, **kwargs):
        # Create a serializer with request.data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Return the success message with OK HTTP status
        return Response({'message': _('Email is available!')})


class CheckPhoneView(GenericAPIView):
    serializer_class = CheckPhoneSerializer
    permission_classes = (AllowAny,)

    def get(self, request, *args, **kwargs):
        return self.finalize_response(request, self.http_method_not_allowed(request, *args, **kwargs), *args, **kwargs)

    def post(self, request, *args, **kwargs):
        # Create a serializer with request.data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Return the success message with OK HTTP status
        return Response({'message': _('Phone number is available!')})


class LoginView(GenericAPIView):
    """
    Check the credentials and return the REST Token
    if the credentials are valid and authenticated.
    Calls Django Auth login method to register User ID
    in Django session framework

    Accept the following POST parameters: email, password
    Return the REST Framework Token Object's key.
    """
    serializer_class = LoginSerializer
    permission_classes = (AllowAny,)

    @sensitive_post_parameters_m
    def dispatch(self, *args, **kwargs):
        return super(LoginView, self).dispatch(*args, **kwargs)

    def get_response(self):
        token = self.user.access_token
        response = Response(
            {
                'category': self.user.category,
                'types': self.user.types,
                'domains': get_domains(self.request, self.user, token),
                'token': token
            }
        )
        cookie_name = getattr(settings, 'JWT_AUTH_COOKIE', None)
        cookie_secure = getattr(settings, 'JWT_AUTH_SECURE', False)
        cookie_httponly = getattr(settings, 'JWT_AUTH_HTTPONLY', True)
        cookie_samesite = getattr(settings, 'JWT_AUTH_SAMESITE', 'Lax')

        if cookie_name:
            expiration = (datetime.utcnow() + jwt_settings.ACCESS_TOKEN_LIFETIME)
            response.set_cookie(
                cookie_name,
                token,
                expires=expiration,
                secure=cookie_secure,
                httponly=cookie_httponly,
                samesite=cookie_samesite
            )
        return response

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.user = serializer.validated_data

        return self.get_response()


class UserViewSet(SerializerClassMixin, ModelViewSet):
    serializer_class = UserSerializer
    serializer_action_classes = {
        'verify': ValidateTokenSerializer,
        'change_password': ChangePasswordSerializer
    }
    permission_classes = (AllowAny,)
    filter_backends = [filters.SearchFilter]
    search_fields = ['first_name', 'last_name', 'email', 'phone']

    def get_queryset(self):
        queryset = User.objects.filter(accounts__in=[self.request.tenant.id], is_suspended=False). \
            order_by('first_name', 'last_name')

        if self.action != 'contact' and self.request.query_params.get('type') != 'all':
            queryset = queryset.filter(is_active=True)

        return queryset

    def list(self, request, *args, **kwargs):
        if self.request.query_params.get('source') == 'photo-bank':
            return Response([user.short_dict() for user in
                             self.filter_queryset(self.get_queryset().filter(category__in=['Customer', 'Tenant']).
                                                  exclude(id=self.request.user.id))])

        elif self.request.query_params.get('source') == 'chat':
            return Response([user.short_dict() for user in
                             self.filter_queryset(self.get_queryset().filter(category=self.request.user.category).
                                                  exclude(id=self.request.user.id))])

        elif self.request.query_params.get('source') == 'inbox':
            if self.request.query_params.get('type') == 'tenant':
                return Response([user.mail_dict() for user in
                                 self.filter_queryset(self.get_queryset().filter(category='Tenant'))])

            elif self.request.query_params.get('type') == 'all':
                return Response([user.contact_short() for user in
                                 self.filter_queryset(self.get_queryset().exclude(category='Owner Group'))])

            return Response([user.mail_dict() for user in self.filter_queryset(
                self.get_queryset().filter(category='Customer', types__overlap=['Manager', 'Owner']))
                             for group in user.groups.filter(is_active=True) if 'Inbox' in group.can_add])

        elif self.request.query_params.get('source') == 'report':
            if self.request.query_params.get('type') == 'engineer':
                return Response([user.mail_dict() for user in
                                 self.filter_queryset(self.get_queryset().filter(category='Customer',
                                                                                 types__contains=['Engineer']))])

        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'], url_path='contact', permission_classes=[AllowAny])
    def contact(self, request, pk=None):
        return Response(self.get_object().contact())

    @action(detail=False, methods=['post'], permission_classes=[AllowAny], url_path='verify', url_name='verify')
    def verify(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = EmailVerification.objects.select_related('user').get(token=request.data.get('token')).user
        data = {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'phone': str(user.phone)
        }

        if user.category == 'Vendor':
            vendor = user.vendor_member.vendor
            data.update({
                'company_name': vendor.company.name,
                'categories': [
                    {'id': category.id, 'name': category.name}
                    for category in vendor.categories.all()
                ],
            })

        return Response(data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['put'], url_path='change-password')
    def change_password(self, request, pk=None):
        user = self.get_object()
        user_keycloak = request.user
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        realm = user.oidc_profile.realm.name
        user_id = user_keycloak.oidc_profile.user_id_remote
        server = user.oidc_profile.realm.server
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {user_keycloak.access_token}",
        }
        data = {
            "value": request.data['new_password'],
        }
        url = f'{server}auth/admin/realms/{realm}/users/{user_id}/reset-password'
        response = requests.put(url, data=json.dumps(data), headers=headers)
        if response.status_code != 204:
            return Response({'message': _('Error unknown.')}, status=response.status_code)
        return Response({'message': _('Password changed successfully.')})

    @action(detail=False, methods=['get'], url_path='profile', url_name='profile')
    def profile(self, request):
        account = request.tenant
        data = request.user.get_profile_web()

        if request.is_mobile:
            data = request.user.get_profile_mobile()
            data['migrated_to_new_version'] = account.migrated_to_new_version

        data.update({'account': account.id, "schema": account.schema_name})
        return Response(data)

    @action(detail=False, methods=['get'], url_path='auth', url_name='auth')
    def auth(self, request):
        user = request.user
        if not user.is_send_first_email:
            send_welcome_email(user.id)
            user.is_send_first_email = True
            user.save()
        return Response({
            'category': user.category,
            'types': user.types,
            'domains': get_domains(request, request.user),
        })

    @action(detail=False, methods=['post'], permission_classes=[AllowAny], url_path='healthcheck', url_name='healthcheck')
    def healthcheck(self, request):
        return Response({
            'success': True
        })

    def destroy(self, request, *args, **kwargs):
        # TODO Soft delete is implemented. need to check for delete the record.
        instance = self.get_object()

        if instance == request.user:
            return Response({'error': 'You may not delete your own account.'}, status=status.HTTP_400_BAD_REQUEST)

        instance.is_active = False
        instance.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=['get'], url_path='count-by-company')
    def count_by_company(self, request):
        return Response(company_detail_tab_count(eval(self.request.query_params.get("company")), source='user'))

    @action(detail=False, methods=['post'], url_path='cc-users', url_name='cc-users', permission_classes=[AllowAny])
    def create_bulk_user(self, request):
        company_id = request.data.pop('company_id')
        user, created = User.objects.get_or_create(email=request.data.get('email'),
                                                   defaults={'first_name': request.data.get('first_name'),
                                                             'last_name': request.data.get('last_name'),
                                                             'phone': request.data.get('phone'),
                                                             'category': 'Tenant'})
        if created:
            company = Company.objects.get(id=company_id)
            TenantMember.objects.create(tenant=company.tenants.first(), user=user, primary_contact=True)
        #Todo need to change url (fyxt-cc)
        send_welcome_email.delay(str(user.id), sender_id=None, origin='https://docker.devfyxt.com')
        return Response({"user_id": str(user.id)})

    @action(detail=False, methods=['post'], url_path='cc-users-invite', url_name='cc-users-invite',
            permission_classes=[AllowAny])
    def invite_bulk_users(self, request):
        for user in request.data.get('users'):
            try:
                send_welcome_email(user, sender_id=None, origin=request.tenant.origin)
            except:
                pass
        return Response(status=status.HTTP_200_OK)

    @action(detail=True, methods=['get'], url_path='info')
    def info(self, request, pk=None):
        try:
            user = User.objects.get(pk=pk)
            serialized_data = UserShortSearchSerializer(instance=user)
            return Response(data={'user': serialized_data.data})
        except User.DoesNotExist:
            return Response(data={'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response(data={'message': 'Something went wrong'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PermissionLabelViewSet(GenericViewSet, ListModelMixin):
    queryset = PermissionLabel.objects.filter(is_active=True)
    permission_classes = (IsAuthenticated,)
    pagination_class = None

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()

        data = dict()
        for _type in ('View', 'Add', 'Edit', 'Approve', 'Added_Job', 'Delete'):
            permissions = queryset.filter(type=_type)
            if permissions.exists():
                data.update(
                    {
                        _type.lower(): [perm.name for perm in permissions]
                    }
                )

        return Response(data)


class GroupViewSet(ModelViewSet):
    serializer_class = GroupSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['name']

    def get_queryset(self):
        return Group.objects.filter(is_active=True, account=self.request.tenant)

    @has_permissions(['add_group'])
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    @has_permissions(['change_group'])
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    @action(detail=False, methods=['get'], url_path='dropdown')
    def dropdown(self, request):
        return Response([{'id': val.id, 'name': val.name} for val in self.get_queryset()], status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        if instance.users.filter(is_active=True):
            return Response({'error': 'The role is mapped to users. Please unmap and delete.'},
                            status=status.HTTP_400_BAD_REQUEST)

        instance.is_active = False
        instance.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AppleAppSiteAssociationView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request, format=None):
        return Response({
            'applinks': {
                'apps': [],
                'details': [
                    {
                        'appID': '95VZP8ZCNA.com.FYXTLLC.FYXTTENANT',
                        'paths': ['*/password/reset/confirm/*']
                    }
                ]
            }
        })


class UserSettingViewSet(UpdateModelMixin, GenericViewSet):
    queryset = UserSetting.objects.filter(is_active=True)
    serializer_class = UserSettingSerializer
    permission_classes = [IsAuthenticated]


class UserViewViewSet(ContextMixin, ModelViewSet):
    queryset = UserView.objects.filter(is_active=True)
    serializer_class = UserViewsSerializer
    serializer_action_classes = {
        'column': UserColumnsSerializer,
        'column_resize': UserViewsSerializer
    }
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['view_name']

    def get_queryset(self):
        return UserView.objects.filter(is_active=True)

    def get_serializer_class(self):
        try:
            serializer = self.serializer_action_classes[self.action]
            return serializer
        except (KeyError, AttributeError):
            return super().get_serializer_class()

    def create(self, request, *args, **kwargs):
        data = request.data
        serializer = self.get_serializer(data=request.data)

        if view_id := data.get('view_id', None):
            view = UserView.objects.get(id=view_id)
            columns = data.get('column', [column.column_name for column in view.user_columns.filter(is_select=True)])
            data = dict()
            if view.query is not None and view.query.get('column') != '':
                data.update({'column': view.query.get('column'), 'order': view.query.get('order')})
                request.data.update({'query': data})

            serializer = self.get_serializer(data=request.data, context={'columns': columns, 'user': request.user})
            if column := [column.column_name for column in view.user_columns.filter(is_select=True)]:
                if data.get('is_private') is False:
                    if column == data.get('column', []) or data.get('view_name') == view.view_name:
                        return Response("Already published in same format to everyone. So you can't everyone")

        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        return Response(serializer.data, status=status.HTTP_201_CREATED,
                        headers=self.get_success_headers(serializer.data))

    @action(detail=False, methods=['get'], url_path='dashboard_views')
    def dashboard_views(self, request):
        from job.models import Job
        user = self.request.user

        if user.category == 'Customer':
            if 'Owner' in user.types:
                queryset = Job.objects.select_related('category', 'property', 'tenant__company').filter(is_active=True)
            elif 'Manager' in user.types:
                queryset = Job.objects.select_related('category', 'property', 'tenant__company').filter(is_active=True,
                                                                                                        property__managers__user=self.request.user)
            elif 'Engineer' in user.types:
                if Engineer.objects.filter(user_id=self.request.user.id, primary_contact=True):
                    queryset = Job.objects.select_related('category', 'property', 'tenant__company').filter(
                        property__engineers__user=self.request.user, is_active=True).distinct()
                else:
                    queryset = Job.objects.select_related('category', 'property', 'tenant__company').filter(
                        Q(engineers=self.request.user) | Q(created_by=self.request.user), is_active=True).distinct()

        elif user.category == 'Tenant':
            queryset = Job.objects.select_related('category', 'property', 'tenant__company').filter(is_active=True,
                                                    tenant__company=self.request.user.tenant_member.tenant.company)

        # new = apply_job_filter(queryset, _filter='new', user=user).count()
        # _open = apply_job_filter(queryset, _filter='open', user=user).count()

        # if user.category == 'Customer' and "Engineer" not in user.types:
        #     queryset = queryset.filter(type__in=['Regular', 'Emergency'])
        # else:
        #     queryset = queryset.filter(type__in=['Regular', 'Emergency'])

        payload = []
        for view in self.get_queryset().filter(user=user, is_pin=True).order_by('id').distinct('id'):
            data = {
                'id': view.id,
                'name': view.view_name,
                'is_private': view.is_private,
                'is_pin': view.is_pin,
                'make_as_default': view.make_as_default,
                'current_active_tab': view.current_active_tab,
                'query': view.query,
                'is_edit': False if view.created_by is None and view.is_private is False or view.user != user else True,
                'column': []
            }
            for column in UserColumn.objects.filter(view=view, is_select=True):
                if column.column_name == "Job ID":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "id",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Property":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "property",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Brief Description":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "issue_type",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Category":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "category",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Priority":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "priority",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Actions":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "actions",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Service Location":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "location",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Assigned Managers":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "managers",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Assigned Engineers":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "engineers",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Date Created":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "created_at",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Status":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "stage",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Service Type":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "service_type",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Linked Jobs":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "linked_jobs",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Source Type":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "source",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Target Completion Date":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "target_date",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Associated Emails":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "associated_email",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Last Activity":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "modified_at",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Vendor(s)":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "vendors",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Followers":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "followers",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Tenant":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "tenant",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Tenant Contact":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "tenant_contact",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Billable Party":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "billable_party",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Assigned To":
                    data['column'].extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "assigned_to",
                                            'width': column.custom.get('width', '') if column.custom else ''}])
            
            if view.view_name not in ['Assigned To Me', 'Unassigned', 'New Requests', 'Tenant Responsible', 'Requires Attention', 'My Properties']:
                data['count'] = apply_new_dashboard_job_filter(queryset, _filter='All Open Jobs', user=user).count()
                payload.append(data)
                continue
            else:
                data['count'] = apply_new_dashboard_job_filter(queryset, _filter=view.view_name, user=user).count()
                payload.append(data)
                continue

        return Response(payload)

    @action(detail=True, methods=['get', 'post'], url_path='column')
    def column(self, request, pk=None):
        if request.method == 'GET':
            if request.user.user_views.filter(id=str(self.get_object().id)) or self.get_object().is_private is False:
                columns = self.get_object().user_columns.all()
                self.filter_backends = [CustomSearchFilter]
                self.search_fields = ['column_name']
                queryset = self.filter_queryset(columns)
                serializer = self.get_serializer(queryset, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response("this view is private")

        if request.method == 'POST':
            view = request.user.user_views.filter(id=str(self.get_object().id))
            if view:
                if view.filter(created_by=None, is_private=False):
                    return Response("You can\'t Edit standard view. Save as new to edit the columns")

                if data := request.data.get('column'):
                    for column in data:
                        col = self.get_object().user_columns.get(column_name=column)
                        col.is_select = True
                        if custom := request.data.get('custom'):
                            col.custom = custom.get(column) if custom.get(column) else Value('null')
                        col.order = data.index(column) + 1
                        col.save()
                    unselect = self.get_object().user_columns.all().exclude(column_name__in=data)
                    unselect.update(is_select=False, order=0)

                    columns = self.get_object().user_columns.all()
                    serializer = self.get_serializer(columns, many=True)

                    return Response(serializer.data, status=status.HTTP_200_OK)

                elif request.data.get('is_default'):
                    default_column = ['Job ID', 'Last Activity', 'Property', 'Brief Description', 'Category', 'Priority', 'Actions',
                                      'Service Location', 'Assigned Managers', 'Assigned Engineers', 'Date Created',
                                      'Status', 'Service Type', 'Linked Jobs', 'Source Type']
                    for column in default_column:
                        col = self.get_object().user_columns.get(column_name=column)
                        col.is_select = True
                        col.order = default_column.index(column) + 1
                        col.save()

                    unselect = self.get_object().user_columns.all().exclude(column_name__in=default_column)
                    unselect.update(is_select=False, order=0)

                    columns = self.get_object().user_columns.all().exclude(order=0)
                    serializer = self.get_serializer(columns, many=True)

                    return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response('this views are not associated')

    @action(detail=False, methods=['get'], url_path='dropdown')
    def dropdown(self, request):
        queryset = UserView.objects.filter(user=self.request.user, user__accounts=request.tenant).order_by('id') \
            .distinct('id').exclude(is_pin=True)
        standard_views = []
        others_views = []
        my_views = []
        exlcude_views = [view.view_name for view in BaseView.objects.all()]
        exlcude_views.append('My Properties')
        excluded_regex = r'(' + '|'.join(exlcude_views) + ')'

        # This is for standard views
        for view in queryset.filter(created_by=None, is_private=False):
            standard_views.append(
                {
                    'id': view.id,
                    'name': view.view_name
                }
            )

        # This is for created by me views
        for view in queryset.filter(created_by__isnull=False). \
                exclude(view_name__iregex=excluded_regex). \
                order_by('id').distinct('id'):
            my_views.append(
                {
                    'id': view.id,
                    'name': view.view_name,
                    'is_private': view.is_private
                }
            )
        others_view = UserView.objects.filter(is_private=False). \
            exclude(view_name__iregex=excluded_regex).order_by('id').distinct('id')

        # This is for others created views
        for view in others_view.filter(user__accounts=request.tenant).exclude(user=self.request.user):
            others_views.append(
                {
                    'id': view.id,
                    'name': view.view_name,
                    'is_private': view.is_private
                }
            )

        if search := self.request.query_params.get('custom-search'):
            return Response(
                {
                    'standard': [{'id': view.id, 'name': view.view_name}
                                 for view in
                                 queryset.filter(created_by=None, is_private=False, view_name__icontains=search)],
                    'created_by_me': [{'id': view.id, 'name': view.view_name, 'is_private': view.is_private}
                                      for view in
                                      queryset.filter(created_by__isnull=False, view_name__icontains=search).
                                      exclude(view_name__in=[view.view_name for view in BaseView.objects.all()]).
                                      order_by('id').distinct('id')],
                    'others': [{'id': view.id, 'name': view.view_name, 'is_private': view.is_private}
                               for view in
                               others_view.filter(user__accounts=request.tenant, view_name__icontains=search).
                                      exclude(user=self.request.user)],
                }
            )

        else:
            return Response(
                {
                    'standard': standard_views,
                    'created_by_me': my_views,
                    'others': others_views
                }
            )

    @action(detail=True, methods=['post'], url_path='column_resize')
    def column_resize(self, request, pk=None):
        instance = self.get_object()
        data = request.data

        for val in data:
            column = None
            for k, v in val.items():
                if "id" == k:
                    column = instance.user_columns.get(id=v)
                if 'width' == k:
                    column.custom = {'width': v}
                    column.save()

        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_201_CREATED,
                        headers=self.get_success_headers(serializer.data))

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        if not instance.created_by == request.user:
            return Response({'error': _('You can\'t delete this view! It\'s created by others.')},
                            status=status.HTTP_400_BAD_REQUEST)

        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


# Version 2 Dashboard views
class UserDashboardViewViewSet(ContextMixin, ModelViewSet):
    queryset = UserView.objects.filter(is_active=True)
    serializer_class = UserDashboardViewSerializer
    serializer_action_classes = {
        'column': UserDashboardViewColumnsSerializer,
        'column_resize': UserDashboardViewSerializer
    }
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['view_name']

    def get_queryset(self):
        return UserView.objects.filter(is_active=True)

    def get_serializer_class(self):
        try:
            serializer = self.serializer_action_classes[self.action]
            return serializer
        except (KeyError, AttributeError):
            return super().get_serializer_class()

    def create(self, request, *args, **kwargs):
        data = request.data
        serializer = self.get_serializer(data=request.data)

        if view_id := data.get('view_id', None):
            view = UserView.objects.get(id=view_id)
            columns = data.get('column', [column.column_name for column in view.user_columns.filter(is_select=True)])
            data = dict()
            if view.query is not None and view.query.get('column') != '':
                data.update({'column': view.query.get('column'), 'order': view.query.get('order')})
                request.data.update({'query': data})

            serializer = self.get_serializer(data=request.data, context={'columns': columns, 'user': request.user})
            if column := [column.column_name for column in view.user_columns.filter(is_select=True)]:
                if data.get('is_private') is False:
                    if column == data.get('column', []) or data.get('view_name') == view.view_name:
                        return Response("Already published in same format to everyone. So you can't everyone")

        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        return Response(serializer.data, status=status.HTTP_201_CREATED,
                        headers=self.get_success_headers(serializer.data))

    def user_view(self, view_name=None):
        from job.models import Job
        user = self.request.user

        if user.category == 'Customer':
            if 'Owner' in user.types:
                queryset = Job.objects.filter(is_active=True)
            elif 'Manager' in user.types:
                queryset = Job.objects.filter(is_active=True, property__managers__user=user)
            elif 'Engineer' in user.types:
                queryset = Job.objects.filter(Q(engineers=user) | Q(created_by=user), is_active=True).distinct()

        elif user.category == 'Tenant':
            queryset = Job.objects.filter(is_active=True, tenant__company=user.tenant_member.tenant.company)

        if view_name not in ['Assigned To Me', 'Unassigned', 'New Requests', 'Tenant Responsible', 'Requires Attention']:
            data = apply_new_dashboard_job_filter(queryset, _filter=view_name, user=user).count()
        else:
            data = apply_new_dashboard_job_filter(queryset, _filter=view_name, user=user).count()

        return data

    def get_standard_views(self, user=None):
        data = {
            'label': 'Standard Views',
            'type': 'Standard',
            'menus': [{
                'id': view.id,
                'name': view.view_name,
                'default': view.make_as_default,
                'active': view.current_active_tab,
                'count': self.user_view(view_name=view.view_name),
            }for view in self.get_queryset().filter(user=user, is_standard=True).order_by('id').distinct('id')],
        }
        return data

    def get_pinned_views(self, user=None):
        data = {
            'label': 'Pinned Views',
            'type': 'Pinned',
            'menus': [{
                'id': view.id,
                'name': view.view_name,
                'is_private': view.is_private,
                'is_pin': view.is_pin,
                'is_standard': view.is_standard,
                'default': view.make_as_default,
                'active': view.current_active_tab,
                'query': view.query,
                'is_edit': False if view.created_by is None and view.is_private is False or view.user != user else True,
                'count': self.user_view(view_name=view.view_name),
            }for view in self.get_queryset().filter(user=user, is_pin=True).exclude(is_standard=True).order_by('id').distinct('id')]
        }
        return data

    @action(detail=False, methods=['get'], url_path='views')
    def views(self, request):
        standard = self.get_standard_views(user=self.request.user)
        pinned = self.get_pinned_views(user=self.request.user)
        data = standard, pinned
        return Response (data)

    @action(detail=True, methods=['get', 'post'], url_path='column')
    def column(self, request, pk=None):
        instance = self.get_object()
        data = []
        if request.method == 'GET':
            for column in UserColumn.objects.filter(view_id=instance, is_select=True):
                if column.column_name == "Job ID":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "id",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Property":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "property",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Brief Description":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "issue_type",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Category":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "category",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Priority":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "priority",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Actions":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "actions",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Service Location":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "location",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Assigned Managers":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "managers",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Assigned Engineers":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "engineers",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Date Created":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "created_at",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Status":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "stage",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Service Type":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "service_type",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Linked Jobs":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "linked_jobs",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Source Type":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "source",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Target Completion Date":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "target_date",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Associated Emails":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "associated_email",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Last Activity":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "modified_at",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Vendor(s)":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "vendors",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Followers":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "followers",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Tenant":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "tenant",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Tenant Contact":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "tenant_contact",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Billable Party":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "billable_party",
                                            'width': column.custom.get('width', '') if column.custom else ''}])

                if column.column_name == "Assigned To":
                    data.extend([{'id': column.id, 'order': column.order,
                                            'name': column.column_name, 'value': "assigned_to",
                                            'width': column.custom.get('width', '') if column.custom else ''}])
            return Response (data)

        if request.method == 'POST':
            view = request.user.user_views.filter(id=str(self.get_object().id))
            if view:
                if view.filter(created_by=None, is_private=False):
                    return Response("You can\'t Edit standard view. Save as new to edit the columns")

                if data := request.data.get('column'):
                    for column in data:
                        col = self.get_object().user_columns.get(column_name=column)
                        col.is_select = True
                        if custom := request.data.get('custom'):
                            col.custom = custom.get(column) if custom.get(column) else Value('null')
                        col.order = data.index(column) + 1
                        col.save()
                    unselect = self.get_object().user_columns.all().exclude(column_name__in=data)
                    unselect.update(is_select=False, order=0)

                    columns = self.get_object().user_columns.all()
                    serializer = self.get_serializer(columns, many=True)

                    return Response(serializer.data, status=status.HTTP_200_OK)

                elif request.data.get('is_default'):
                    default_column = ['Job ID', 'Property', 'Brief Description', 'Category', 'Priority', 'Actions',
                                      'Service Location', 'Assigned Managers', 'Assigned Engineers', 'Date Created',
                                      'Status', 'Service Type', 'Linked Jobs', 'Source Type']
                    for column in default_column:
                        col = self.get_object().user_columns.get(column_name=column)
                        col.is_select = True
                        col.order = default_column.index(column) + 1
                        col.save()

                    unselect = self.get_object().user_columns.all().exclude(column_name__in=default_column)
                    unselect.update(is_select=False, order=0)

                    columns = self.get_object().user_columns.all().exclude(order=0)
                    serializer = self.get_serializer(columns, many=True)

                    return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response('this views are not associated')

    @action(detail=True, methods=['get', 'post'], url_path='edit-column')
    def edit_column(self, request, pk=None):
        if request.method == 'GET':
            if request.user.user_views.filter(id=str(self.get_object().id)) or self.get_object().is_private is False:
                columns = self.get_object().user_columns.all()
                self.filter_backends = [CustomSearchFilter]
                self.search_fields = ['column_name']
                queryset = self.filter_queryset(columns)
                serializer = UserColumnsSerializer(queryset, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response("this view is private")

    @action(detail=False, methods=['get'], url_path='manage_views')
    def manage_views(self, request):
        queryset = UserView.objects.filter(user=self.request.user, user__accounts=request.tenant).order_by('id').distinct('id')
        others_view = UserView.objects.filter(is_private=False). \
            exclude(view_name__in=[view.view_name for view in BaseView.objects.all()]).order_by('id').distinct('id')

        data = {
            'my_views': queryset.filter(created_by=self.request.user).order_by('id').distinct('id').count(),
            "shared_by_others": others_view.filter(user__accounts=request.tenant).exclude(user=self.request.user).count(),
            'standard_views': queryset.filter(is_standard=True).count()
        }

        return Response (data)

    @action(detail=False, methods=['get'], url_path='my_views')
    def my_views(self, request):
        queryset = UserView.objects.filter(user=self.request.user, user__accounts=request.tenant). \
            exclude(is_standard=True).order_by('id').distinct('id')

        self.filter_backends = [CustomSearchFilter]
        self.search_fields = ['view_name']
        queryset = self.filter_queryset(queryset)

        data = [{
            'id': view.id,
            'name': view.view_name,
            'count': self.user_view(view_name=view.view_name),
            'is_private': view.is_private,
            'default': view.make_as_default,
            'pinned': view.is_pin
        }for view in queryset]

        return Response (data)

    @action(detail=False, methods=['get'], url_path='shared_by_others')
    def shared_by_others(self, request):
        base_query = UserView.objects.filter(is_private=False).exclude(is_standard=True).order_by('id').distinct('id')
        queryset = base_query.filter(user__accounts=request.tenant).exclude(user=self.request.user)

        self.filter_backends = [CustomSearchFilter]
        self.search_fields = ['view_name']
        queryset = self.filter_queryset(queryset)

        data = [{
            'id': view.id,
            'name': view.view_name,
            'count': self.user_view(view_name=view.view_name),
            'default': view.make_as_default,
            'created_by': view.created_by.full_name,
            'is_private': view.is_private,
        }for view in queryset]

        return Response (data)

    @action(detail=False, methods=['get'], url_path='standard_views')
    def standard_views(self, request):
        queryset = UserView.objects.filter(user=self.request.user, user__accounts=request.tenant, is_standard=True).order_by('id') \
            .distinct('id')

        self.filter_backends = [CustomSearchFilter]
        self.search_fields = ['view_name']
        queryset = self.filter_queryset(queryset)

        data = [{
            'id': view.id,
            'name': view.view_name,
            'default': view.make_as_default,
            'count': self.user_view(view_name=view.view_name),
        }for view in queryset]
        return Response (data)

    @action(detail=True, methods=['post'], url_path='column_resize')
    def column_resize(self, request, pk=None):
        instance = self.get_object()
        data = request.data

        for val in data:
            column = None
            for k, v in val.items():
                if "id" == k:
                    column = instance.user_columns.get(id=v)
                if 'width' == k:
                    column.custom = {'width': v}
                    column.save()

        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_201_CREATED,
                        headers=self.get_success_headers(serializer.data))

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        if not instance.created_by == request.user:
            return Response({'error': _('You can\'t delete this view! It\'s Shared by others.')},
                            status=status.HTTP_400_BAD_REQUEST)

        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class LaunchDarklyView(APIView):
    """    This API is used for getting list of feature flags in fyxt Project from launch darkly ,
    this list will be used by frontend for controlling the feature flags    """
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            """ project_key we will get from project key https://app.launchdarkly.com/settings/projects """
            project_key = "default"
            url = "https://app.launchdarkly.com/api/v2/flags/" + project_key
            """ Authorization we will get from https://app.launchdarkly.com/settings/authorization """
            headers = {"Authorization": settings.LAUNCHDARKLY_FYXT_TOKEN}
            response = requests.get(url, headers=headers)
            data = response.json()
            flags = dict()
            for flag in data['items']:
                flags.update({flag['key']: feature_flag_status(self.request.tenant.origin, flag['key'])})
            return Response(flags)
        except Exception as e:
            error_logger(e, sys.exc_info())

    def post(self, request, *args, **kwargs):
        serializer = HealthSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class MailboxViewSet(ModelViewSet):
    """Mailbox Create and Retrieve and list apis used in new inbox development"""
    serializer_class = MailboxSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['email']

    def get_queryset(self):
        return Mailbox.objects.filter(is_active=True, account=self.request.tenant, email__isnull=False)

    @has_permissions(['add_mailbox'])
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    @action(detail=True, methods=['get'], url_path='supported-timezones')
    def supported_timezones(self, request, pk=None):
        timezone_data = [
            {
                "alias": "Dateline Standard Time",
                "displayName": "(UTC-12:00) International Date Line West"
            },
            {
                "alias": "Samoa Standard Time",
                "displayName": "(UTC+13:00) Samoa"
            },
            {
                "alias": "UTC-11",
                "displayName": "(UTC-11:00) Coordinated Universal Time-11"
            },
            {
                "alias": "Aleutian Standard Time",
                "displayName": "(UTC-10:00) Aleutian Islands"
            },
            {
                "alias": "Hawaiian Standard Time",
                "displayName": "(UTC-10:00) Hawaii"
            },
            {
                "alias": "Marquesas Standard Time",
                "displayName": "(UTC-09:30) Marquesas Islands"
            },
            {
                "alias": "Alaskan Standard Time",
                "displayName": "(UTC-09:00) Alaska"
            },
            {
                "alias": "UTC-09",
                "displayName": "(UTC-09:00) Coordinated Universal Time-09"
            },
            {
                "alias": "Yukon Standard Time",
                "displayName": "(UTC-07:00) Yukon"
            },
            {
                "alias": "Pacific Standard Time (Mexico)",
                "displayName": "(UTC-08:00) Baja California"
            },
            {
                "alias": "UTC-08",
                "displayName": "(UTC-08:00) Coordinated Universal Time-08"
            },
            {
                "alias": "Pacific Standard Time",
                "displayName": "(UTC-08:00) Pacific Time (US & Canada)"
            },
            {
                "alias": "US Mountain Standard Time",
                "displayName": "(UTC-07:00) Arizona"
            },
            {
                "alias": "Mountain Standard Time (Mexico)",
                "displayName": "(UTC-07:00) Chihuahua, La Paz, Mazatlan"
            },
            {
                "alias": "Mountain Standard Time",
                "displayName": "(UTC-07:00) Mountain Time (US & Canada)"
            },
            {
                "alias": "Eastern Standard Time (Mexico)",
                "displayName": "(UTC-05:00) Chetumal"
            },
            {
                "alias": "Central America Standard Time",
                "displayName": "(UTC-06:00) Central America"
            },
            {
                "alias": "Central Standard Time",
                "displayName": "(UTC-06:00) Central Time (US & Canada)"
            },
            {
                "alias": "Easter Island Standard Time",
                "displayName": "(UTC-06:00) Easter Island"
            },
            {
                "alias": "Central Standard Time (Mexico)",
                "displayName": "(UTC-06:00) Guadalajara, Mexico City, Monterrey"
            },
            {
                "alias": "Canada Central Standard Time",
                "displayName": "(UTC-06:00) Saskatchewan"
            },
            {
                "alias": "SA Pacific Standard Time",
                "displayName": "(UTC-05:00) Bogota, Lima, Quito, Rio Branco"
            },
            {
                "alias": "Eastern Standard Time",
                "displayName": "(UTC-05:00) Eastern Time (US & Canada)"
            },
            {
                "alias": "Haiti Standard Time",
                "displayName": "(UTC-05:00) Haiti"
            },
            {
                "alias": "Cuba Standard Time",
                "displayName": "(UTC-05:00) Havana"
            },
            {
                "alias": "US Eastern Standard Time",
                "displayName": "(UTC-05:00) Indiana (East)"
            },
            {
                "alias": "Turks And Caicos Standard Time",
                "displayName": "(UTC-05:00) Turks and Caicos"
            },
            {
                "alias": "Venezuela Standard Time",
                "displayName": "(UTC-04:00) Caracas"
            },
            {
                "alias": "Magallanes Standard Time",
                "displayName": "(UTC-03:00) Punta Arenas"
            },
            {
                "alias": "Paraguay Standard Time",
                "displayName": "(UTC-04:00) Asuncion"
            },
            {
                "alias": "Atlantic Standard Time",
                "displayName": "(UTC-04:00) Atlantic Time (Canada)"
            },
            {
                "alias": "Central Brazilian Standard Time",
                "displayName": "(UTC-04:00) Cuiaba"
            },
            {
                "alias": "SA Western Standard Time",
                "displayName": "(UTC-04:00) Georgetown, La Paz, Manaus, San Juan"
            },
            {
                "alias": "Pacific SA Standard Time",
                "displayName": "(UTC-04:00) Santiago"
            },
            {
                "alias": "Newfoundland Standard Time",
                "displayName": "(UTC-03:30) Newfoundland"
            },
            {
                "alias": "Tocantins Standard Time",
                "displayName": "(UTC-03:00) Araguaina"
            },
            {
                "alias": "E. South America Standard Time",
                "displayName": "(UTC-03:00) Brasilia"
            },
            {
                "alias": "SA Eastern Standard Time",
                "displayName": "(UTC-03:00) Cayenne, Fortaleza"
            },
            {
                "alias": "Argentina Standard Time",
                "displayName": "(UTC-03:00) City of Buenos Aires"
            },
            {
                "alias": "Greenland Standard Time",
                "displayName": "(UTC-03:00) Greenland"
            },
            {
                "alias": "Montevideo Standard Time",
                "displayName": "(UTC-03:00) Montevideo"
            },
            {
                "alias": "Saint Pierre Standard Time",
                "displayName": "(UTC-03:00) Saint Pierre and Miquelon"
            },
            {
                "alias": "Bahia Standard Time",
                "displayName": "(UTC-03:00) Salvador"
            },
            {
                "alias": "UTC-02",
                "displayName": "(UTC-02:00) Coordinated Universal Time-02"
            },
            {
                "alias": "Mid-Atlantic Standard Time",
                "displayName": "(UTC-02:00) Mid-Atlantic - Old"
            },
            {
                "alias": "Azores Standard Time",
                "displayName": "(UTC-01:00) Azores"
            },
            {
                "alias": "Cape Verde Standard Time",
                "displayName": "(UTC-01:00) Cabo Verde Is."
            },
            {
                "alias": "UTC",
                "displayName": "(UTC) Coordinated Universal Time"
            },
            {
                "alias": "GMT Standard Time",
                "displayName": "(UTC+00:00) Dublin, Edinburgh, Lisbon, London"
            },
            {
                "alias": "Greenwich Standard Time",
                "displayName": "(UTC+00:00) Monrovia, Reykjavik"
            },
            {
                "alias": "Morocco Standard Time",
                "displayName": "(UTC+01:00) Casablanca"
            },
            {
                "alias": "W. Europe Standard Time",
                "displayName": "(UTC+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna"
            },
            {
                "alias": "Central Europe Standard Time",
                "displayName": "(UTC+01:00) Belgrade, Bratislava, Budapest, Ljubljana, Prague"
            },
            {
                "alias": "Romance Standard Time",
                "displayName": "(UTC+01:00) Brussels, Copenhagen, Madrid, Paris"
            },
            {
                "alias": "Central European Standard Time",
                "displayName": "(UTC+01:00) Sarajevo, Skopje, Warsaw, Zagreb"
            },
            {
                "alias": "W. Central Africa Standard Time",
                "displayName": "(UTC+01:00) West Central Africa"
            },
            {
                "alias": "Libya Standard Time",
                "displayName": "(UTC+02:00) Tripoli"
            },
            {
                "alias": "Namibia Standard Time",
                "displayName": "(UTC+02:00) Windhoek"
            },
            {
                "alias": "Jordan Standard Time",
                "displayName": "(UTC+02:00) Amman"
            },
            {
                "alias": "GTB Standard Time",
                "displayName": "(UTC+02:00) Athens, Bucharest"
            },
            {
                "alias": "Middle East Standard Time",
                "displayName": "(UTC+02:00) Beirut"
            },
            {
                "alias": "Egypt Standard Time",
                "displayName": "(UTC+02:00) Cairo"
            },
            {
                "alias": "E. Europe Standard Time",
                "displayName": "(UTC+02:00) Chisinau"
            },
            {
                "alias": "Syria Standard Time",
                "displayName": "(UTC+02:00) Damascus"
            },
            {
                "alias": "West Bank Standard Time",
                "displayName": "(UTC+02:00) Gaza, Hebron"
            },
            {
                "alias": "South Africa Standard Time",
                "displayName": "(UTC+02:00) Harare, Pretoria"
            },
            {
                "alias": "FLE Standard Time",
                "displayName": "(UTC+02:00) Helsinki, Kyiv, Riga, Sofia, Tallinn, Vilnius"
            },
            {
                "alias": "Israel Standard Time",
                "displayName": "(UTC+02:00) Jerusalem"
            },
            {
                "alias": "South Sudan Standard Time",
                "displayName": "(UTC+02:00) Juba"
            },
            {
                "alias": "Kaliningrad Standard Time",
                "displayName": "(UTC+02:00) Kaliningrad"
            },
            {
                "alias": "Sudan Standard Time",
                "displayName": "(UTC+02:00) Khartoum"
            },
            {
                "alias": "Turkey Standard Time",
                "displayName": "(UTC+03:00) Istanbul"
            },
            {
                "alias": "Belarus Standard Time",
                "displayName": "(UTC+03:00) Minsk"
            },
            {
                "alias": "Arabic Standard Time",
                "displayName": "(UTC+03:00) Baghdad"
            },
            {
                "alias": "Arab Standard Time",
                "displayName": "(UTC+03:00) Kuwait, Riyadh"
            },
            {
                "alias": "Russian Standard Time",
                "displayName": "(UTC+03:00) Moscow, St. Petersburg"
            },
            {
                "alias": "E. Africa Standard Time",
                "displayName": "(UTC+03:00) Nairobi"
            },
            {
                "alias": "Astrakhan Standard Time",
                "displayName": "(UTC+04:00) Astrakhan, Ulyanovsk"
            },
            {
                "alias": "Russia Time Zone 3",
                "displayName": "(UTC+04:00) Izhevsk, Samara"
            },
            {
                "alias": "Saratov Standard Time",
                "displayName": "(UTC+04:00) Saratov"
            },
            {
                "alias": "Volgograd Standard Time",
                "displayName": "(UTC+03:00) Volgograd"
            },
            {
                "alias": "Iran Standard Time",
                "displayName": "(UTC+03:30) Tehran"
            },
            {
                "alias": "Arabian Standard Time",
                "displayName": "(UTC+04:00) Abu Dhabi, Muscat"
            },
            {
                "alias": "Azerbaijan Standard Time",
                "displayName": "(UTC+04:00) Baku"
            },
            {
                "alias": "Mauritius Standard Time",
                "displayName": "(UTC+04:00) Port Louis"
            },
            {
                "alias": "Georgian Standard Time",
                "displayName": "(UTC+04:00) Tbilisi"
            },
            {
                "alias": "Caucasus Standard Time",
                "displayName": "(UTC+04:00) Yerevan"
            },
            {
                "alias": "Afghanistan Standard Time",
                "displayName": "(UTC+04:30) Kabul"
            },
            {
                "alias": "West Asia Standard Time",
                "displayName": "(UTC+05:00) Ashgabat, Tashkent"
            },
            {
                "alias": "Ekaterinburg Standard Time",
                "displayName": "(UTC+05:00) Ekaterinburg"
            },
            {
                "alias": "Pakistan Standard Time",
                "displayName": "(UTC+05:00) Islamabad, Karachi"
            },
            {
                "alias": "Qyzylorda Standard Time",
                "displayName": "(UTC+05:00) Qyzylorda"
            },
            {
                "alias": "India Standard Time",
                "displayName": "(UTC+05:30) Chennai, Kolkata, Mumbai, New Delhi"
            },
            {
                "alias": "Sri Lanka Standard Time",
                "displayName": "(UTC+05:30) Sri Jayawardenepura"
            },
            {
                "alias": "Nepal Standard Time",
                "displayName": "(UTC+05:45) Kathmandu"
            },
            {
                "alias": "Central Asia Standard Time",
                "displayName": "(UTC+06:00) Astana"
            },
            {
                "alias": "Bangladesh Standard Time",
                "displayName": "(UTC+06:00) Dhaka"
            },
            {
                "alias": "Omsk Standard Time",
                "displayName": "(UTC+06:00) Omsk"
            },
            {
                "alias": "Altai Standard Time",
                "displayName": "(UTC+07:00) Barnaul, Gorno-Altaysk"
            },
            {
                "alias": "N. Central Asia Standard Time",
                "displayName": "(UTC+07:00) Novosibirsk"
            },
            {
                "alias": "Tomsk Standard Time",
                "displayName": "(UTC+07:00) Tomsk"
            },
            {
                "alias": "Myanmar Standard Time",
                "displayName": "(UTC+06:30) Yangon (Rangoon)"
            },
            {
                "alias": "SE Asia Standard Time",
                "displayName": "(UTC+07:00) Bangkok, Hanoi, Jakarta"
            },
            {
                "alias": "W. Mongolia Standard Time",
                "displayName": "(UTC+07:00) Hovd"
            },
            {
                "alias": "North Asia Standard Time",
                "displayName": "(UTC+07:00) Krasnoyarsk"
            },
            {
                "alias": "China Standard Time",
                "displayName": "(UTC+08:00) Beijing, Chongqing, Hong Kong, Urumqi"
            },
            {
                "alias": "North Asia East Standard Time",
                "displayName": "(UTC+08:00) Irkutsk"
            },
            {
                "alias": "Singapore Standard Time",
                "displayName": "(UTC+08:00) Kuala Lumpur, Singapore"
            },
            {
                "alias": "W. Australia Standard Time",
                "displayName": "(UTC+08:00) Perth"
            },
            {
                "alias": "Taipei Standard Time",
                "displayName": "(UTC+08:00) Taipei"
            },
            {
                "alias": "Ulaanbaatar Standard Time",
                "displayName": "(UTC+08:00) Ulaanbaatar"
            },
            {
                "alias": "Transbaikal Standard Time",
                "displayName": "(UTC+09:00) Chita"
            },
            {
                "alias": "North Korea Standard Time",
                "displayName": "(UTC+09:00) Pyongyang"
            },
            {
                "alias": "Aus Central W. Standard Time",
                "displayName": "(UTC+08:45) Eucla"
            },
            {
                "alias": "Tokyo Standard Time",
                "displayName": "(UTC+09:00) Osaka, Sapporo, Tokyo"
            },
            {
                "alias": "Korea Standard Time",
                "displayName": "(UTC+09:00) Seoul"
            },
            {
                "alias": "Yakutsk Standard Time",
                "displayName": "(UTC+09:00) Yakutsk"
            },
            {
                "alias": "Cen. Australia Standard Time",
                "displayName": "(UTC+09:30) Adelaide"
            },
            {
                "alias": "AUS Central Standard Time",
                "displayName": "(UTC+09:30) Darwin"
            },
            {
                "alias": "E. Australia Standard Time",
                "displayName": "(UTC+10:00) Brisbane"
            },
            {
                "alias": "AUS Eastern Standard Time",
                "displayName": "(UTC+10:00) Canberra, Melbourne, Sydney"
            },
            {
                "alias": "West Pacific Standard Time",
                "displayName": "(UTC+10:00) Guam, Port Moresby"
            },
            {
                "alias": "Tasmania Standard Time",
                "displayName": "(UTC+10:00) Hobart"
            },
            {
                "alias": "Vladivostok Standard Time",
                "displayName": "(UTC+10:00) Vladivostok"
            },
            {
                "alias": "Bougainville Standard Time",
                "displayName": "(UTC+11:00) Bougainville Island"
            },
            {
                "alias": "Magadan Standard Time",
                "displayName": "(UTC+11:00) Magadan"
            },
            {
                "alias": "Sakhalin Standard Time",
                "displayName": "(UTC+11:00) Sakhalin"
            },
            {
                "alias": "Lord Howe Standard Time",
                "displayName": "(UTC+10:30) Lord Howe Island"
            },
            {
                "alias": "Russia Time Zone 10",
                "displayName": "(UTC+11:00) Chokurdakh"
            },
            {
                "alias": "Norfolk Standard Time",
                "displayName": "(UTC+11:00) Norfolk Island"
            },
            {
                "alias": "Central Pacific Standard Time",
                "displayName": "(UTC+11:00) Solomon Is., New Caledonia"
            },
            {
                "alias": "Russia Time Zone 11",
                "displayName": "(UTC+12:00) Anadyr, Petropavlovsk-Kamchatsky"
            },
            {
                "alias": "New Zealand Standard Time",
                "displayName": "(UTC+12:00) Auckland, Wellington"
            },
            {
                "alias": "UTC+12",
                "displayName": "(UTC+12:00) Coordinated Universal Time+12"
            },
            {
                "alias": "Fiji Standard Time",
                "displayName": "(UTC+12:00) Fiji"
            },
            {
                "alias": "Kamchatka Standard Time",
                "displayName": "(UTC+12:00) Petropavlovsk-Kamchatsky - Old"
            },
            {
                "alias": "Chatham Islands Standard Time",
                "displayName": "(UTC+12:45) Chatham Islands"
            },
            {
                "alias": "UTC+13",
                "displayName": "(UTC+13:00) Coordinated Universal Time+13"
            },
            {
                "alias": "Tonga Standard Time",
                "displayName": "(UTC+13:00) Nuku'alofa"
            },
            {
                "alias": "Line Islands Standard Time",
                "displayName": "(UTC+14:00) Kiritimati Island"
            }
        ]
        return Response({'supported_timezone': timezone_data})

    @action(detail=True, methods=['put'], url_path='update')
    def update_mail_box(self, request, pk=None):
        try:
            mailbox = self.get_object()

            next_preferred_tz = request.data.get('preferred_tz', None)
            if next_preferred_tz:
                mailbox.preferred_tz = next_preferred_tz
                mailbox.save()

            return Response({'success': True})
        except Exception as e:
            return Response({'success': False})

    @has_permissions(['add_mailbox'])
    @action(detail=False, methods=['post'], url_path='outlook-oauth-url')
    def outlook_oauth_url(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance: Mailbox = serializer.create(serializer.validated_data)
        url, state = get_outlook_oauth_url(instance.id, settings.OUTLOOK_REDIRECT_URI)
        instance.oauth_state = state
        instance.save()
        return JsonResponse({'url': url}, status=status.HTTP_200_OK)

    # Allowing any user to access this method as this will be called against root api tenant.
    @action(detail=False, methods=['get'], url_path='outlook-oauth-code', permission_classes=[AllowAny])
    def outlook_oauth_code(self, request):
        state: str = request.GET.get('state')
        # Manually adding https as django is not responsible for ssl, so it receives domain as http
        request_url: str = "https://{0}{1}".format(request.get_host(), request.get_full_path())
        instance: Mailbox = None
        try:
            instance = Mailbox.objects.get(oauth_state=state)
            email = get_outlook_token(instance.id, request_url, state, settings.OUTLOOK_REDIRECT_URI)
            if email is None:
                raise Exception("Failed to login to Outlook")

            # Re fetch mailbox to get the token saved by previous function call
            instance = Mailbox.objects.get(oauth_state=state)
            instance.email = email
            instance.save()

            return MailboxViewSet.redirect_to_inbox(instance.redirect_url)
        except Exception as e:
            error_logger(e, sys.exc_info())
            redirect_url = instance.redirect_url if instance is not None else None
            # When error and without instance redirect to first domain
            return MailboxViewSet.redirect_to_inbox(redirect_url)

    @staticmethod
    def redirect_to_inbox(url: str):
        url = url if url is not None else Domain.objects.first().origin
        return redirect(url)


@api_view(['get'])
@permission_classes([AllowAny])
def get_account_logo(request):
    fyxt_logo = "https://fyxt.com/wp-content/themes/fyxt/assets/img/logo.svg"
    if not request.tenant:
        return redirect(fyxt_logo)

    if not request.tenant.company:
        return redirect(fyxt_logo)

    if not request.tenant.company.logo:
        return redirect(fyxt_logo)

    return redirect(request.tenant.company.logo.url)


class CompanyContactTypeViewSet(ContextMixin, ModelViewSet):
    serializer_class = CompanyContactTypeSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = None
    def get_queryset(self):
        source = self.request.query_params.get('source')
        return CompanyContactType.objects.filter(is_active=True, category=source)


class CompanyPropertyViewSet(ContextMixin, ModelViewSet):
    queryset = Company.objects.filter(is_active=True)
    serializer_class = CompanyPropertyViewSetSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = LimitOffsetPagination

    def get_queryset(self):
        queryset = Company.objects.filter(is_active=True)
        return queryset
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        queryset = Property.objects.filter(company_properties__company_id=instance.id). \
                   values('id', 'name', 'serial_number', 'property_address__city__name', 'property_address__state__name','property_address__address', 'property_address__zipcode')

        if search := self.request.query_params.get('search'):
            queryset = queryset.filter(Q(serial_number__icontains=search) | Q(name__icontains=search))
        if column := self.request.query_params.get('ordering'):
            serializer = self.get_serializer(queryset, many=True)
            queryset = ordering(serializer, column)
            page = self.paginate_queryset(queryset)
            if page is not None:
                return self.get_paginated_response(page)
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class ContactPropertyViewSet(ContextMixin, ModelViewSet):
    queryset = Contact.objects.filter(is_active=True)
    serializer_class = CompanyPropertyViewSetSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = LimitOffsetPagination

    def get_queryset(self):
        queryset = Contact.objects.filter(is_active=True)
        return queryset

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        if company:=self.request.query_params.get('company'):
            property = [property.property.id for property in CompanyProperty.objects.filter(company__id__in=eval(company))]
            queryset = Property.objects.filter(is_active=True, id__in=property).\
                values('id', 'name', 'serial_number', 'property_address__city__name', 'property_address__state__name','property_address__address', 'property_address__zipcode')
        else:
            queryset = Property.objects.filter(is_active=True)

        if search := self.request.query_params.get('search'):
            queryset = queryset.filter(Q(id__icontains=search) | Q(property_address__address__icontains=search))
        if column := self.request.query_params.get('ordering'):
            serializer = self.get_serializer(queryset, many=True)
            queryset = ordering(serializer, column)
            page = self.paginate_queryset(queryset)
            if page is not None:
                return self.get_paginated_response(page)
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class CompanyJobViewSet(ContextMixin, ModelViewSet):
    queryset = Company.objects.filter(is_active=True)
    serializer_class = CompanyJobViewSetSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = LimitOffsetPagination

    def get_queryset(self):
        queryset = Company.objects.filter(is_active=True)
        return queryset

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        if self.request.query_params.get('type') == 'Tenant':
            queryset = Job.objects.filter(is_active=True,
                                          tenant__in=instance.tenants.select_related('tenant__id').all().values_list(
                                              'id', flat=True)).values('id', 'property__name', 'issue_type',
                                                                       'category__name')
        elif self.request.query_params.get('type') == 'Vendor':
            queryset = Job.objects.filter(vendors__vendor__in=instance.vendors.select_related('vendor__id').all().\
                values_list('id',flat=True)).values('id', 'property__name', 'issue_type', 'category__name')

        else:
            queryset = Job.objects.filter(
                property__in=CompanyProperty.objects.filter(company_id=instance.id).values_list('property_id',flat=True)).\
                values('id', 'property__name', 'issue_type', 'category__name')

        if search := self.request.query_params.get('search'):
            queryset = queryset.filter(Q(id__icontains=search) | Q(property__name__icontains=search))
        if column := self.request.query_params.get('ordering'):
            serializer = self.get_serializer(queryset, many=True)
            queryset = ordering(serializer, column)
            page = self.paginate_queryset(queryset)
            if page is not None:
                return self.get_paginated_response(page)
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class ContactJobViewSet(ContextMixin, ModelViewSet):
    queryset = Contact.objects.filter(is_active=True)
    serializer_class = CompanyJobViewSetSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = LimitOffsetPagination

    def get_queryset(self):
        queryset = Contact.objects.filter(is_active=True)
        return queryset
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()

        if company:=self.request.query_params.get('company'):
            property = [property.property.id for property in CompanyProperty.objects.filter(company__id__in=eval(company))]
            queryset = Job.objects.filter(is_active=True, property__id__in=property).values('id', 'property__name', 'issue_type', 'category__name')
        else:
            queryset = Job.objects.filter(is_active=True)

        if search := self.request.query_params.get('search'):
            queryset = queryset.filter(Q(id__icontains=search) | Q(property__name__icontains=search))
        if column := self.request.query_params.get('ordering'):
            serializer = self.get_serializer(queryset, many=True)
            queryset = ordering(serializer, column)
            page = self.paginate_queryset(queryset)
            if page is not None:
                return self.get_paginated_response(page)
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class CompanyViewSet(APIView):
    """This View for create and update company from Fyxt cc"""
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        create_company(request.data)
        return Response(status=status.HTTP_201_CREATED)


class UserSearchViewSet(ContextMixin, ModelViewSet):
    queryset = User.objects.filter(is_active=True, is_suspended=False)
    serializer_class = {
        'search': UserDropDownSerializer,
    }
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]

    @action(detail=False, methods=['get'], url_path='search')
    def search(self, request):
        search_term = request.GET.get('q')
        search_condition = Q(first_name__iexact=search_term) | Q(last_name__iexact=search_term)
        queryset = self.get_queryset().filter(search_condition, accounts=request.tenant).order_by('first_name')
        queryset = self.filter_queryset(queryset)
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = UserDropDownSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = UserDropDownSerializer(queryset, many=True)
        return Response(serializer.data)

# @api_view(['post'])
# @permission_classes([IsAuthenticated])
# def get_user_information(request):
#     user_id = request.data.get('user_id')
#     try:
#         user = User.objects.get(pk=user_id)
#         serialized_data = UserShortSearchSerializer(instance=user)
#         return Response(data={'user': serialized_data.data})
#     except User.DoesNotExist:
#         return Response(data={'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
#     except Exception as e:
#         return Response(data={'message': 'Something went wrong'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

class HealthCheckView(APIView):
    """
    This view is to check whether the backend server is live or not
    """
    permission_classes = (AllowAny,)

    def get(self, request, *args, **kwargs):
        return Response({'Message': 'Success'}, status=status.HTTP_200_OK)
