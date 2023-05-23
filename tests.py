import json
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from .models import User, EmailVerification
from fyxt.utils import get_api_url as api
from django_tenants.test.cases import TenantTestCase
from django_tenants.test.client import TenantClient
from account.models import User as accountUser
from account.models import *

client = APIClient()
content_type = 'application/json'



"""PASSWORD RESET"""
class PasswordResetTestCase(TenantTestCase):
    """TOKEN BASED AUTHENTICATION"""

    @classmethod
    def setup_tenant(cls, tenant):
        tenant.name = "test"
        return tenant

    @staticmethod
    def get_test_tenant_domain():
        return 'localhost'

    def setUp(self):
        super().setUp()
        self.c = TenantClient(self.tenant)
        user = accountUser.objects.create_user(email='admin@mailinator.com', password='12345678', phone='+91z23456700')
        user.accounts.add(self.c.tenant)
        user.save()
        self.password_reset = {'email': 'admin@mailinator.com'}
        self.password_reset_confirm = {'new_password1': "87654321", 'new_password2': "87654321"}

    def test_password_reset(self):
        url = "http://tenant.test.com/v1/password/reset/"
        user = accountUser.objects.get(email='admin@mailinator.com')
        # email_verification = EmailVerification.objects.create(user=user, is_active=True, is_verified=True)
        email_verification = EmailVerification.objects.create(user=user)

        # POST PASSWORD_RESET
        password_reset_response = self.c.post(path=url, data=self.password_reset, content_type="application/json")
        self.assertEqual(password_reset_response.status_code, status.HTTP_200_OK)

        # POST PASSWORD_RESET_CONFIRM
        # # password_verify_user = accountUser.objects.get(email='admin@mailinator.com')
        # # email_verification = EmailVerification.objects.get(user=user)
        # self.password_reset_confirm_id = str(user.id)
        # self.user_token = str(email_verification.token)
        # self.password_reset_confirm.update({"uid": self.password_reset_confirm_id, "token": self.user_token})
        # password_reset_confirm_url = url + "confirm/"
        # password_reset_confirm_response = self.c.post(path=password_reset_confirm_url, data=self.password_reset_confirm, content_type="application/json")


""" TEST CASE FOR LOGIN AND LOGOUT """


class UserAuthenticationTestCase(TenantTestCase):
    """Token Based Authentication"""
    @classmethod
    def setup_tenant(cls, tenant):
        tenant.name = "test"
        return tenant

    @staticmethod
    def get_test_tenant_domain():
        return 'localhost'

    def setUp(self):
        super().setUp()
        self.c = TenantClient(self.tenant)
        user = accountUser.objects.create_user(email='admin@mailinator.com', password='12345678', phone='+91z23456700')
        user.accounts.add(self.c.tenant)
        user.save()
        self.valid_data = {'email': 'admin@mailinator.com', 'password': '12345678'}

    def test_valid_login(self):
        url = "http://tenant.test.com/v1/"
        user = accountUser.objects.get(email='admin@mailinator.com')
        email_verification = EmailVerification.objects.create(user=user, is_active=True, is_verified=True)

        # POST USER_LOGIN
        login_url = url + "login/"
        login_response = self.c.post(path=login_url, data=self.valid_data, content_type="application/json")
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)

        # POST USER_LOGOUT
        logout_url = url + "logout/"
        logout_response = self.c.post(path=logout_url, data=self.valid_data, content_type="application/json")
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)

    @classmethod
    def tearDownClass(cls):
        # connection.set_schema_to_public()
        cls.domain.delete()
        cls.tenant.delete(force_drop=True)
        cls.remove_allowed_test_domain()


class UserTestCase(TenantTestCase):
    """Token Based Authentication"""
    @classmethod
    def setup_tenant(cls, tenant):
        tenant.name = "test"
        return tenant

    def setUp(self):
        super().setUp()
        self.c = TenantClient(self.tenant)
        user = accountUser.objects.create_user(email='admin@mailinator.com', password='12345678', phone='+91z23456700')
        user.save()
        user.accounts.add(self.c.tenant)
        self.valid_data = {'email': 'admin@mailinator.com', 'password': '12345678'}
        self.invalid_data = {'email': 'admin123@mailinator.com', 'password': '12345678'}
        self.user_create = {"accounts": [str(self.c.tenant.id)], "category": "Fyxt", "types": ["Owner"],
                            "email": "pokrishna@gmail.com", "recovery_email": "jap@gmail.com", "phone": "+919990001111",
                            "first_name": "krishna", "last_name": "Po", "live": True,
                            "is_first_ticket_created": True, "is_first_time_login": True, "notes": "string",
                            "gender": "Male", "popup": True, "is_active": True }
        self.update_data = {"accounts": [str(self.c.tenant.id)], "category": "Fyxt",  "types": ["Owner"],
                            "email": "pokrishna@gmail.com","recovery_email":"jap123@gmail.com","phone": "+919990001111",
                            "first_name": "kitty", "last_name": "PK", "gender": "Male", "popup": True,
                            "is_first_ticket_created": True,"is_first_time_login": True,"live": True,
                            "notes": "PM", "is_active": True}
        self.patch_data = {"accounts": [str(self.c.tenant.id)], "category": "Fyxt",  "types": ["Owner"],
                            "email": "krishna@gmail.com","recovery_email":"jap@gmail.com","phone": "+919990001111",
                            "first_name": "kitty", "last_name": "PK", "gender": "Male", "popup": True,
                            "is_first_ticket_created": True,"is_first_time_login": True,"live": True,
                            "notes": "PM", "is_active": True}
        self.change_password = {"current_password": "12345678", "new_password": "india@123",
                                "confirm_new_password": "india@123"}

    def test_valid_user(self):
        user = accountUser.objects.get(email='admin@mailinator.com')
        headers = 'Bearer ' + user.token

        # POST USER_CREATE
        url = "http://tenant.test.com/v1/users/"
        user_create_response = self.c.post(path=url, data=json.dumps(self.user_create), HTTP_AUTHORIZATION=headers, content_type="application/json")
        self.assertEqual(user_create_response.status_code, status.HTTP_201_CREATED)

        # GET USER_LIST
        user_get_url = url
        user_get_response = self.c.get(path=user_get_url, HTTP_AUTHORIZATION=headers, content_type="application/json")
        self.assertEqual(user_get_response.status_code, status.HTTP_200_OK)

        # GET USER_PROFILE
        user_profile_url = url + "profile/"
        user_profile_response = self.c.get(path=user_profile_url, HTTP_AUTHORIZATION=headers, content_type="application/json")
        self.assertEqual(user_profile_response.status_code, status.HTTP_200_OK)

        # POST USER_VERIFY
        user_verify_url = url + "verify/"
        user = accountUser.objects.get(email='admin@mailinator.com')
        email_verification = EmailVerification.objects.create(user=user)
        self.user_token = str(email_verification.token)
        user_verify_response = self.c.post(path=user_verify_url, data={"token": self.user_token}, HTTP_AUTHORIZATION=headers, content_type="application/json")
        self.assertEqual(user_verify_response.status_code, status.HTTP_200_OK)

        # GET SEARCH_USER
        user_search_url = url + "?search='kitty'"
        user_search_response = self.c.get(path=user_search_url, HTTP_AUTHORIZATION=headers, content_type="application/json")
        self.assertEqual(user_search_response.status_code, status.HTTP_200_OK)

        # GET USER_READ
        user_read_id = user_create_response.data['id']
        user_read_url = url + user_read_id + "/"
        user_read_account = accountUser.objects.get(email='pokrishna@gmail.com')
        user_read_headers = 'Bearer ' + user_read_account.token
        user_read_response = self.c.get(path=user_read_url, HTTP_AUTHORIZATION=user_read_headers, content_type="application/json")
        self.assertEqual(user_read_response.status_code, status.HTTP_200_OK)

        # # Get User Properties
        # url = "http://tenant.test.com/v1/users/" + str(user.id) + '/properties/'
        # response = self.c.get(path=url, HTTP_AUTHORIZATION=user_read_headers, content_type="application/json")
        # self.assertEqual(response.status_code, status.HTTP_200_OK)

        # PUT USERS_UPDATE
        user_put_id = user_create_response.data['id']
        user_put_url = url + user_put_id + "/"
        user_put_response = self.c.put(path=user_put_url, data=self.update_data, HTTP_AUTHORIZATION=user_read_headers, content_type="application/json")
        self.assertEqual(user_put_response.status_code, status.HTTP_200_OK)

        # PATCH USERS_UPDATE
        user_patch_id = user_create_response.data['id']
        user_patch_url = url + user_patch_id + "/"
        user_patch_response = self.c.patch(path=user_patch_url, data=self.patch_data, HTTP_AUTHORIZATION=user_read_headers, content_type="application/json")
        self.assertEqual(user_patch_response.status_code, status.HTTP_200_OK)

        # PUT USER_CHANGE_PASSWORD
        user_read_account.set_password('12345678')
        user_read_account.save()
        user_change_password_id = user_create_response.data['id']
        user_change_password_url = url + user_change_password_id + '/change-password/'
        user_change_password_response = self.c.put(path=user_change_password_url, data=self.change_password, HTTP_AUTHORIZATION=user_read_headers, content_type="application/json")
        self.assertEqual(user_change_password_response.status_code, status.HTTP_200_OK)

        # DELETE USER
        delete_user_id = str(user.id)
        delete_user_url = url + delete_user_id + "/"
        delete_user_response = self.c.delete(path=delete_user_url, HTTP_AUTHORIZATION=user_read_headers, content_type="application/json")
        self.assertEqual(delete_user_response.status_code, status.HTTP_204_NO_CONTENT) 

    @classmethod
    def tearDownClass(cls):
        # connection.set_schema_to_public()
        cls.domain.delete()
        cls.tenant.delete(force_drop=True)
        cls.remove_allowed_test_domain()


class GroupTestCase(TenantTestCase):
    """Token Based Authentication"""
    @classmethod
    def setup_tenant(cls, tenant):
        tenant.name = "test"
        return tenant

    def setUp(self):
        super().setUp()
        self.c = TenantClient(self.tenant)
        user = accountUser.objects.create_user(email='admin@mailinator.com', password='12345678', phone='+91z23456700')
        user.is_superuser = True
        user.save()
        user.accounts.add(self.c.tenant)
        self.valid_data = {'email': 'admin@mailinator.com', 'password': '12345678'}
        self.group_data = {"name": "Test", "can_view": ["Properties"], "can_add": ["Properties", "Clients", "Tenants",
        "Abstracts", "Vendors", "Jobs", "Accounts", "Standard Roles", "Abstract Templates", "Property Permissions"],
                           "can_change": [], "can_delete": [], "can_approve": ["Job Requests", "Costs", "Schedules"]}
        self.group_update = {"name": "MyGroup", "can_view": ["Properties"], "can_change": ["Properties"],
                             "can_add": ["Properties", "Tenants", "Vendors", "work orders", "owners", "abstracts",
                                         "accounts"], "can_delete": [],
                             "can_approve": ["job requests", "bids", "schedules"]}

    def test_valid_group(self):
        user = accountUser.objects.get(email='admin@mailinator.com')
        headers = 'Bearer ' + user.token

        # POST GROUP_CREATE
        url = "http://tenant.test.com/v1/groups/"
        create_group_response = self.c.post(path=url, data=self.group_data, HTTP_AUTHORIZATION=headers, content_type="application/json")
        self.assertEqual(create_group_response.status_code, status.HTTP_201_CREATED)

        # GET GROUP_DETAILS
        get_group_id = create_group_response.data['id']
        get_group_url = url + get_group_id + "/"
        get_group_response = self.c.get(path=get_group_url, HTTP_AUTHORIZATION=headers, content_type="application/json")
        self.assertEqual(get_group_response.status_code, status.HTTP_200_OK)

        # GET LIST_OF_GROUPS
        get_group_list_url = url
        get_group_list_response = self.c.get(path=get_group_list_url, HTTP_AUTHORIZATION=headers, content_type="application/json")
        self.assertEqual(get_group_list_response.status_code, status.HTTP_200_OK)

        # GET GROUP_SEARCH
        get_group_search_url = url + "?search='Test'"
        get_group_search_response = self.c.get(path=get_group_search_url, HTTP_AUTHORIZATION=headers, content_type="application/json")
        self.assertEqual(get_group_search_response.status_code, status.HTTP_200_OK)

        # Get- /v1/permission-labels Permission labels
        label_url = "http://tenant.test.com/v1/permission-labels/"
        response = self.c.get(path=label_url, HTTP_AUTHORIZATION=headers, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # GET GROUP_DROPDOWN
        get_group_dropdown_url = url + "dropdown/"
        get_group_dropdown_response = self.c.get(path=get_group_dropdown_url, HTTP_AUTHORIZATION=headers, content_type="application/json")
        self.assertEqual(get_group_dropdown_response.status_code, status.HTTP_200_OK)

        # PUT UPDATE_GROUP
        put_group_id = create_group_response.data['id']
        put_group_url = url + put_group_id + "/"
        put_group_response = self.c.put(path=put_group_url, data=self.group_update, HTTP_AUTHORIZATION=headers, content_type="application/json")
        self.assertEqual(put_group_response.status_code, status.HTTP_200_OK)

        # PATCH UPDATE_GROUP
        patch_group_id = create_group_response.data['id']
        patch_group_url = url + patch_group_id + "/"
        patch_group_response = self.c.patch(path=patch_group_url, data=self.group_update, HTTP_AUTHORIZATION=headers, content_type="application/json")
        self.assertEqual(patch_group_response.status_code, status.HTTP_200_OK)

        # DELETE_GROUP
        delete_group_id = create_group_response.data['id']
        delete_group_url = url + delete_group_id + "/"
        delete_group_response = self.c.delete(path=delete_group_url, data=self.group_update, HTTP_AUTHORIZATION=headers, content_type="application/json")
        self.assertEqual(delete_group_response.status_code, status.HTTP_204_NO_CONTENT)

    @classmethod
    def tearDownClass(cls):
        # connection.set_schema_to_public()
        cls.domain.delete()
        cls.tenant.delete(force_drop=True)
        cls.remove_allowed_test_domain()


class CategoriesTestCase(TenantTestCase):
    """Token Based Authentication"""
    @classmethod
    def setup_tenant(cls, tenant):
        tenant.name = "test"
        return tenant

    def setUp(self):
        super().setUp()
        self.c = TenantClient(self.tenant)

    def test_valid_Categories(self):
        # GET CATEGORIES_LIST
        get_categories_url = "http://tenant.test.com/v1/categories/"
        get_categories_response = self.c.get(path=get_categories_url, content_type="application/json")
        self.assertEqual(get_categories_response.status_code, status.HTTP_200_OK)

    @classmethod
    def tearDownClass(cls):
        # connection.set_schema_to_public()
        cls.domain.delete()
        cls.tenant.delete(force_drop=True)
        cls.remove_allowed_test_domain()


"""CHECK EMAIL AND CHECK PHONE"""


class CheckEmailandPhone(TenantTestCase):
    """TOKEN BASED AUTHENTICATION"""
    @classmethod
    def setup_tenant(cls, tenant):
        tenant.name = "test"
        return tenant

    @staticmethod
    def get_test_tenant_domain():
        return 'localhost'

    def setUp(self):
        super().setUp()
        self.c = TenantClient(self.tenant)
        self.check_email = {'email': 'admin3@mailinator.com'}
        self.check_phone = {'phone': "+918765432123"}
    
    def test_check_email_and_phone(self):
        url = "http://tenant.test.com/v1/check/"

        # POST CHECK_EMAIL
        check_email_url = url + "email/"
        check_email_response = self.c.post(path=check_email_url, data=self.check_email, content_type="application/json")
        self.assertEqual(check_email_response.status_code, status.HTTP_200_OK)

        # POST CHECK_PHONE
        check_phone_url = url + "phone/"
        check_phone_response = self.c.post(path=check_phone_url, data=self.check_phone, content_type="application/json")
        self.assertEqual(check_phone_response.status_code, status.HTTP_200_OK)


class CountryTestCase(TenantTestCase):
    """Token Based Authentication"""
    @classmethod
    def setup_tenant(cls, tenant):
        tenant.name = "test"
        return tenant

    def setUp(self):
        super().setUp()
        self.c = TenantClient(self.tenant)

    def test_valid_country(self):

        # GET COUNTRIES_LIST
        get_countries_url = "http://tenant.test.com/v1/countries/"
        get_countries_response = self.c.get(path=get_countries_url, content_type="application/json")
        self.assertEqual(get_countries_response.status_code, status.HTTP_200_OK)

    @classmethod
    def tearDownClass(cls):
        # connection.set_schema_to_public()
        cls.domain.delete()
        cls.tenant.delete(force_drop=True)
        cls.remove_allowed_test_domain()


class StatesTestCase(TenantTestCase):
    """Token Based Authentication"""
    @classmethod
    def setup_tenant(cls, tenant):
        tenant.name = "test"
        return tenant

    def setUp(self):
        super().setUp()
        self.c = TenantClient(self.tenant)

    def test_valid_states(self):
        # GET STATES_LIST
        get_states_url = "http://tenant.test.com/v1/states/"
        get_states_response = self.c.get(path=get_states_url, content_type="application/json")
        self.assertEqual(get_states_response.status_code, status.HTTP_200_OK)

        # GET STATE_BY_COUNTRY
        get_state_by_country_url = get_states_url + "?country="
        get_state_by_country_response = self.c.get(path=get_state_by_country_url, content_type="application/json")
        self.assertEqual(get_state_by_country_response.status_code, status.HTTP_200_OK)

    @classmethod
    def tearDownClass(cls):
        # connection.set_schema_to_public()
        cls.domain.delete()
        cls.tenant.delete(force_drop=True)
        cls.remove_allowed_test_domain()


class CitiesTestCase(TenantTestCase):
    """Token Based Authentication"""
    @classmethod
    def setup_tenant(cls, tenant):
        tenant.name = "test"
        return tenant

    @staticmethod
    def get_test_tenant_domain():
        return 'localhost'

    def setUp(self):
        super().setUp()
        self.c = TenantClient(self.tenant)

    def test_valid_cities(self):
        # GET CITIES_LIST
        get_cities_url = "http://tenant.test.com/v1/cities/"
        get_cities_response = self.c.get(path=get_cities_url, content_type="application/json")
        self.assertEqual(get_cities_response.status_code, status.HTTP_200_OK)

        # GET CITIES_BY_STATE
        get_cities_by_state_url = get_cities_url + "?state="
        get_cities_by_state_response = self.c.get(path=get_cities_by_state_url, content_type="application/json")
        self.assertEqual(get_cities_by_state_response.status_code, status.HTTP_200_OK)

    @classmethod
    def tearDownClass(cls):
        # connection.set_schema_to_public()
        cls.domain.delete()
        cls.tenant.delete(force_drop=True)
        cls.remove_allowed_test_domain()


class PermissionLableTestCase(TenantTestCase):
    """Token Based Authentication"""
    @classmethod
    def setup_tenant(cls, tenant):
        tenant.name = "test"
        return tenant

    def setUp(self):
        super().setUp()
        self.c = TenantClient(self.tenant)
        user = accountUser.objects.create_user(email='admin@mailinator.com', password='12345678', phone='+91z23456700')
        user.is_superuser = True
        user.save()
        user.accounts.add(self.c.tenant)

    def test_valid_group(self):
        user = accountUser.objects.get(email='admin@mailinator.com')
        headers = 'Bearer ' + user.token

        # GET Method
        url = "http://tenant.test.com/v1/permission-labels/"
        create_group_response = self.c.get(path=url, HTTP_AUTHORIZATION=headers, content_type="application/json")
        self.assertEqual(create_group_response.status_code, status.HTTP_200_OK)

    @classmethod
    def tearDownClass(cls):
        # connection.set_schema_to_public()
        cls.domain.delete()
        cls.tenant.delete(force_drop=True)
        cls.remove_allowed_test_domain()
