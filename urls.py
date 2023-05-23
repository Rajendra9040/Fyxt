from dj_rest_auth.views import LogoutView, PasswordResetView, PasswordResetConfirmView
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from fyxt.utils import get_api_url as api
from .views import (
    CountryViewSet,
    StateViewSet,
    CityViewSet,
    CategoryViewSet,
    CheckEmailView,
    CheckPhoneView,
    LoginView,
    PermissionLabelViewSet,
    GroupViewSet,
    UserViewSet,
    AppleAppSiteAssociationView,
    UserSettingViewSet,
    UserViewViewSet,
    LaunchDarklyView,
    MailboxViewSet,
    get_account_logo,
    CompanyContactTypeViewSet,
    CompanyPropertyViewSet,
    ContactPropertyViewSet,
    CompanyJobViewSet,
    ContactJobViewSet,
    CompanyViewSet,
    UserDashboardViewViewSet,
    UserSearchViewSet,
    HealthCheckView
)

# Version 1
router = DefaultRouter()
router.register(r'countries', CountryViewSet, 'countries')
router.register(r'states', StateViewSet, 'states')
router.register(r'cities', CityViewSet, 'cities')
router.register(r'fyxt-categories', CategoryViewSet, 'fyxt_categories')
router.register(r'permission-labels', PermissionLabelViewSet, 'permission_labels')
router.register(r'groups', GroupViewSet, 'groups')
router.register(r'users', UserViewSet, 'users')
router.register(r'user-settings', UserSettingViewSet, 'user_setting')
router.register(r'user-views', UserViewViewSet, 'user_view')
router.register(r'mailbox', MailboxViewSet, 'mailbox')
router.register(r'company-types', CompanyContactTypeViewSet, 'company-types')
router.register(r'company-properties', CompanyPropertyViewSet, 'company-properties')
router.register(r'contact-properties', ContactPropertyViewSet, 'contact-properties')
router.register(r'contact-jobs', ContactJobViewSet, 'contact-jobs')
router.register(r'company-jobs', CompanyJobViewSet, 'company-jobs')
router.register(r'ms/users', UserSearchViewSet, 'user-search')

# Version 2
router_v2 = DefaultRouter()
router_v2.register(r'dashboard', UserDashboardViewViewSet, 'dashboard')

urlpatterns = [
    path(api(), include(router.urls)),
    path(api(url_name='account/logo'), get_account_logo),
    path(api(url_name='check/email'), CheckEmailView.as_view(), name='check_email'),
    path(api(url_name='check/phone'), CheckPhoneView.as_view(), name='check_phone'),
    path(api(url_name='login'), LoginView.as_view(), name='login'),
    path(api(url_name='password/reset'), PasswordResetView.as_view(), name='password_reset'),
    path(api(url_name='password/reset/confirm'), PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path(api(url_name='logout'), LogoutView.as_view(), name='logout'),
    path(api(url_name='launch_darkly'), LaunchDarklyView.as_view(), name='launch_darkly'),
    path(api(url_name='companies'), CompanyViewSet.as_view(), name='companies'),

    # Health Check
    path(api(url_name='health-check'), HealthCheckView.as_view(), name='health-check'),

    # IOS configurations
    path('apple-app-site-association', AppleAppSiteAssociationView.as_view(), name='apple_app_site_association'),

    # Version 2
    path(api(version='v2'), include(router_v2.urls)),
]
