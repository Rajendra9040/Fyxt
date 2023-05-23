import uuid
from contextlib import suppress

import pyotp
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, GroupManager, Permission, PermissionsMixin
from django.contrib.postgres.fields import ArrayField
from django.core.exceptions import ObjectDoesNotExist
from django.db import models, connections, transaction
from django.utils.translation import ugettext_lazy as _
from django_tenants.postgresql_backend.base import _check_schema_name
from django_tenants.utils import schema_exists, get_public_schema_name, get_tenant_database_alias
from django_tenants.models import TenantMixin, DomainMixin
from phonenumber_field.modelfields import PhoneNumberField
from rest_framework_simplejwt.tokens import RefreshToken
from django.db.models import Q

from fyxt.utils import get_api_domain, get_cleaned_permissions, sms


class AbstractBaseModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    is_active = models.BooleanField(default=True)

    class Meta:
        abstract = True


class BaseModel(AbstractBaseModel):
    created_by = models.ForeignKey('account.User', verbose_name=_('Created by'), on_delete=models.SET_NULL,
                                   editable=False,
                                   null=True, related_name="created_%(class)s_set")
    modified_by = models.ForeignKey('account.User', verbose_name=_('Modified by'), on_delete=models.SET_NULL,
                                    editable=False,
                                    null=True, related_name="modified_%(class)s_set")
    created_at = models.DateTimeField(_('Created at'), auto_now_add=True)
    modified_at = models.DateTimeField(_('Modified at'), auto_now=True)

    class Meta:
        abstract = True


class Country(AbstractBaseModel):
    name = models.CharField(_('Name'), max_length=100, unique=True)
    iso = models.CharField(_('ISO'), max_length=2, unique=True, db_index=True,
                           help_text=_('2 letter country code (Example: US for United States)'))
    iso3 = models.CharField(_('ISO3'), max_length=3, unique=True,
                            help_text=_('3 letter country code (Example: US for United States)'))
    calling_code = models.CharField(_('Calling code'), max_length=10,
                                    help_text=_('Telephone calling code (Example: +1 for United States)'))

    def save(self, **kwargs):
        if not self.pk:
            self.name = self.name.title()
        super(Country, self).save()

    def __str__(self):
        return self.name

    class Meta:
        db_table = 'country'
        verbose_name = _('Country')
        verbose_name_plural = _('Countries')
        ordering = ('name',)


class State(AbstractBaseModel):
    country = models.ForeignKey(Country, verbose_name=_('Country'), on_delete=models.CASCADE, related_name='states')
    name = models.CharField(_('Name'), max_length=100)
    abbreviation = models.CharField(_('Abbreviation'), max_length=30, blank=True)

    def save(self, **kwargs):
        if not self.pk:
            self.name = self.name.upper()
        super(State, self).save()

    def __str__(self):
        return self.name.title()

    class Meta:
        db_table = 'state'
        unique_together = ('country', 'name')
        verbose_name = _('State')
        verbose_name_plural = _('States')
        ordering = ('name',)


class City(AbstractBaseModel):
    state = models.ForeignKey(State, verbose_name=_('State'), on_delete=models.CASCADE, related_name='cities')
    name = models.CharField(_('Name'), max_length=100)

    def save(self, **kwargs):
        if not self.pk:
            self.name = self.name.upper()
        super(City, self).save()

    def __str__(self):
        return self.name.title()

    class Meta:
        db_table = 'city'
        unique_together = ('state', 'name')
        verbose_name = _('City')
        verbose_name_plural = _('Cities')
        ordering = ('name',)


class Currency(AbstractBaseModel):
    name = models.CharField(verbose_name=_('Name'), max_length=100)
    code = models.CharField(verbose_name=_('Code'), max_length=3, unique=True)
    symbol = models.CharField(verbose_name=_('Symbol'), max_length=4, blank=True)

    def save(self, **kwargs):
        self.name = self.name.title()
        self.code = self.code.upper()

        super(Currency, self).save()

    def __str__(self):
        return '{0} [{1}]'.format(self.name, self.code)

    class Meta:
        db_table = 'currency'
        verbose_name = _('Currency')
        verbose_name_plural = _('Currencies')
        ordering = ('code',)


class Category(AbstractBaseModel):
    name = models.CharField(_('Name'), max_length=50, unique=True)
    description = models.TextField(_('Description'), blank=True)

    def save(self, **kwargs):
        from .tasks import sync_category
        if not self.id:
            self.name = self.name.title()
        sync_category.delay(self.name, is_active=self.is_active)
        super(Category, self).save()

    def __str__(self):
        return self.name

    class Meta:
        db_table = 'fyxt_category'
        verbose_name = _('Category')
        verbose_name_plural = _('Categories')
        ordering = ('name',)


class Address(BaseModel):
    TYPES = (('Legal', 'Legal'), ('Registered', 'Registered'), ('Operating', 'Operating'))

    name = models.CharField(_('Name'), max_length=50, blank=True)
    type = models.CharField(_('Type'), choices=TYPES, max_length=20, blank=True)
    address = models.TextField(_('Address'))
    country = models.ForeignKey(Country, verbose_name=_('Country'), related_name="%(class)s_set", null=True,
                                on_delete=models.SET_NULL)
    state = models.ForeignKey(State, verbose_name=_('State'), related_name="%(class)s_set", null=True,
                              on_delete=models.SET_NULL)
    city = models.ForeignKey(City, verbose_name=_('City'), related_name="%(class)s_set", null=True,
                             on_delete=models.SET_NULL)
    zipcode = models.CharField(_('Zipcode'), max_length=10)
    primary = models.BooleanField(_('Primary'), default=False)

    def __str__(self):
        address = self.address
        if self.city:
            address = f'{address}, {self.city.name}'
        if self.state:
            address = f'{address}, {self.state.name}'
        if self.country:
            address = f'{address}, {self.country.name}'

        return f'{address}, {self.zipcode}'

    class Meta:
        abstract = True

    def to_dict(self):
        fields = ['id', 'type', 'address', 'zipcode']
        data = {f: getattr(self, f) for f in fields}
        data['city'] = {'id': self.city.id, 'name': self.city.name} if self.city else {}
        data['state'] = {'id': self.state.id, 'name': self.state.name} if self.state else {}
        data['country'] = {'id': self.country.id, 'name': self.country.name} if self.country else {}

        return data

    def to_string(self):
        return self.__str__()

    @transaction.atomic
    def save(self, *args, **kwargs):
        if not self.country:
            self.country = Country.objects.get(iso=settings.DEFAULT_REGION)

        super().save(*args, **kwargs)


class Company(BaseModel):
    TYPES = (('Customer', 'Customer'), ('Tenant', 'Tenant'), ('Vendor', 'Vendor'),
             ('Asset Management', 'Asset Management'), ('Ownership Entity', 'Ownership Entity'))

    name = models.CharField(_('Company Name'), max_length=255, db_index=True)
    crm_id = models.UUIDField(_('CRM ID'), editable=False, null=True, blank=True)
    entity_name = models.CharField(_('Entity Name'), max_length=255, blank=True)
    type = models.CharField(_('Type'), choices=TYPES, max_length=25,
                            help_text=_('This filed is mandatory to group Tenant/Vendor/Owner Groups'))
    ein = models.CharField(_('EIN Number'), max_length=25, blank=True, help_text=_('Employer Identification Number'))
    vat = models.CharField(verbose_name=_('VAT Number'), max_length=30, blank=True, help_text=_('Company VAT number'))
    duns = models.CharField(verbose_name=_('DUNS Number'), max_length=9, blank=True, help_text=_('Company DUNS number'))
    currency = models.ForeignKey(Currency, verbose_name=_('Base Currency'), related_name='companies', null=True, blank=True, on_delete=models.SET_NULL)
    email = models.EmailField(verbose_name=_('Email'), max_length=200, blank=True, help_text=_('Email'))
    phone = PhoneNumberField(verbose_name=_('Phone'), blank=True, help_text=_('Phone Number'))
    fax = PhoneNumberField(verbose_name=_('Fax'), blank=True, help_text=_('Fax Number'))
    website = models.URLField(verbose_name=_('Website'), blank=True, help_text=_('Company website'))
    logo = models.ImageField(verbose_name=_('Logo'), upload_to='logos', null=True, blank=True,
                             help_text=_('Company logo'))

    def __str__(self):
        return self.name

    @property
    def address(self):
        return self.addresses.select_related('country', 'state', 'city').filter(primary=True).first()

    @property
    def address_dict(self):
        if address := self.address:
            return {
                'address': address.address,
                'country': address.country.name if address.country else '',
                'state': address.state.name if address.state else '',
                'city': address.city.name if address.city else '',
                'zipcode': address.zipcode
            }

        return {}

    class Meta:
        db_table = 'company'
        verbose_name = _('Company')
        verbose_name_plural = _('Companies')
        ordering = ('name',)


class CompanyAddress(Address):
    company = models.ForeignKey(Company, verbose_name=_('Company'), related_name='addresses', on_delete=models.CASCADE)

    class Meta:
        db_table = 'company_address'
        verbose_name = _('Company Address')
        verbose_name_plural = _('Company Addresses')
        unique_together = ('name', 'company')

    @transaction.atomic
    def save(self, *args, **kwargs):
        # Get all other primary address
        address_list = self.__class__.objects.filter(company=self.company, primary=True).exclude(pk=self.pk)
        self.primary = self.primary or (not address_list.exists())
        if self.primary:
            address_list.update(primary=False)

        if not self.country:
            self.country = Country.objects.get(iso=settings.DEFAULT_REGION)

        super().save(*args, **kwargs)


class Plan(BaseModel, TenantMixin):
    """
    This is the model will hold all subscription related plan information
    """
    name = models.CharField(_('Name'), max_length=255, unique=True)
    no_of_pm_users = models.PositiveIntegerField(_('Number of PM users'))
    no_of_tenants = models.PositiveIntegerField(_('Number of tenants'))
    no_of_vendors = models.PositiveIntegerField(_('Number of vendors'))
    description = models.TextField(_('Description'), blank=True)

    def __str__(self):
        return self.name

    class Meta:
        db_table = 'plan'
        verbose_name = _('Plan')
        verbose_name_plural = _('Plans')
        ordering = ('name',)


class Account(BaseModel):
    auto_drop_schema = False
    """
    USE THIS WITH CAUTION!
    Set this flag to true on a parent class if you want the schema to be
    automatically deleted if the tenant row gets deleted.
    """

    name = models.CharField(_('Name'), max_length=255, unique=True)
    schema_name = models.CharField(max_length=63, unique=True, db_index=True, validators=[_check_schema_name])
    short_name = models.CharField(_('Short Name'), max_length=4)
    company = models.ForeignKey(Company, verbose_name=_('Company'), related_name='accounts', null=True, blank=True,
                                on_delete=models.SET_NULL)
    on_trial = models.BooleanField(_('On Trial'), default=True)
    paid_until = models.DateField(_('Paid Until'), null=True, blank=True)
    plan = models.ForeignKey(Plan, verbose_name=_('Plan'), related_name='accounts', null=True, blank=True,
                             on_delete=models.SET_NULL)
    # migrated_to_new_version is the temporary field for the accounts created before 15th April 2023
    migrated_to_new_version = models.BooleanField(_('Is migrated to new version?'), default=False)

    def __str__(self):
        return self.name

    class Meta:
        db_table = 'account'
        verbose_name = _('Account')
        verbose_name_plural = _('Accounts')
        ordering = ('name',)

    def save(self, **kwargs):
        new = False
        if not self.id:
            new = True
            self.id = uuid.uuid4()  # TO get pk/id before save the instance
            self.name = self.name.title()

        if new and settings.RUN_AUTO_MIGRATIONS:
            from administrator.tasks import setup_account  # TO avoid circular dependency
            # Setup account and load default data 
            setup_account.delay(account=self.id, schema=self.schema_name, delay=5)

        super(Account, self).save()

    def _drop_schema(self, force_drop=False):
        """ Drops the schema"""
        connection = connections[get_tenant_database_alias()]
        has_schema = hasattr(connection, 'schema_name')
        if has_schema and connection.schema_name not in (self.schema_name, get_public_schema_name()):
            raise Exception(f"Can't delete tenant outside it's own schema or the public schema. Current schema is {connection.schema_name}.")

        if has_schema and schema_exists(self.schema_name) and (self.auto_drop_schema or force_drop):
            self.pre_drop()
            cursor = connection.cursor()
            cursor.execute(f'DROP SCHEMA "{self.schema_name}" CASCADE')

    def pre_drop(self):
        """
        This is a routine which you could override to backup the tenant schema before dropping.
        :return:
        """

    def delete(self, force_drop=False, *args, **kwargs):
        """
        Deletes this row. Drops the tenant's schema if the attribute
        auto_drop_schema set to True.
        """
        self._drop_schema(force_drop)
        super().delete(*args, **kwargs)


class Domain(BaseModel, DomainMixin):
    domain = models.CharField(_('API Domain'), max_length=255, unique=True, db_index=True,
                              help_text=_('API endpoint domain to identify the schema. '
                                          'Ex. transwestern.apifyxt.com will return the public schema'))
    origin = models.URLField(_('Origin'), unique=True, db_index=True,
                             help_text=_('This is the origin which the UI client is running on. '
                                         'Ex. https://transwestern.fyxt.com is mapped to transwestern.apifyxt.com '
                                         'as per above example'))

    class Meta:
        db_table = 'domain'
        verbose_name = _('Domain')
        verbose_name_plural = _('Domains')

    @transaction.atomic
    def save(self, *args, **kwargs):
        # Get all other primary domains with the same tenant
        domain_list = self.__class__.objects.filter(tenant=self.tenant, is_primary=True).exclude(pk=self.pk)
        # If we have no primary domain yet, set as primary domain by default
        self.is_primary = self.is_primary or (not domain_list.exists())
        if self.is_primary:
            # Remove primary status of existing domains for tenant
            domain_list.update(is_primary=False)

        # Clean up trailing slash / in origin
        self.origin = self.origin.strip('/')

        # Set domain from origin
        if not self.domain:
            self.domain = get_api_domain(self.origin)
            
        super().save(*args, **kwargs)


class Mailbox(BaseModel):
    """Mailbox configurations"""
    TYPES = (('Outlook', 'Outlook'), ('Gmail', 'Gmail'), ('Smtp', 'Smtp'))

    account = models.ForeignKey(Account, verbose_name=_('Account'), related_name='mailboxes',
                                related_query_name='mailbox', on_delete=models.CASCADE)
    host = models.CharField(_('Host'), max_length=1024, blank=True,
                            help_text='For office365, smtp.outlook.office365.com; for Gsuite, smtp.gmail.com')
    email = models.EmailField(_('email'), null=True)
    password = models.CharField(_('password'), max_length=255, blank=True)
    port = models.PositiveSmallIntegerField(_('Port'), default=587, help_text='For Gsuite, 465')
    use_tls = models.BooleanField(_('Use TLS?'), default=True)
    primary = models.BooleanField(default=True, db_index=True)
    type = models.CharField(_('Type'), choices=TYPES, max_length=25, default='Smtp')  # Type of MailServer will be used
    token = models.CharField(_('Token'), max_length=65536, null=True, blank=True)  # Applicable for Outlook & Gmail types
    oauth_state = models.CharField(_('Oath State'), max_length=1024, null=True, blank=True)
    redirect_url = models.CharField(_('Redirect Url'), max_length=1024, null=True, blank=True)
    name = models.CharField(_('Name'), max_length=1024, null=True, blank=True)  # Name of the Mailbox
    preferred_tz = models.CharField(_('Preferred Timezone'), max_length=32, default='Eastern Standard Time')  # Timezone for this mailbox

    class Meta:
        db_table = 'mailbox'
        verbose_name = _('Mailbox')
        verbose_name_plural = _('Mailbox')

    @transaction.atomic
    def save(self, *args, **kwargs):
        # self.password = encrypt(self.password)
        # Get all other primary domains with the same tenant
        mailbox_list = self.__class__.objects.filter(account=self.account, primary=True).exclude(pk=self.pk)
        # If we have no primary mailbox yet, set as primary mailbox by default
        self.primary = self.primary or (not mailbox_list.exists())
        if self.primary:
            # Remove primary status of existing mailbox for account
            mailbox_list.update(primary=False)

        super().save(*args, **kwargs)


class PermissionLabel(AbstractBaseModel):
    """
    This is the admin configuration table for maintain UI level permissions operations
    """
    TYPES = (('View', 'View'), ('Add', 'Add'), ('Change', 'Change'), ('Approve', 'Approve'),
             ('Added_Job', 'Added_Job'), ('Delete', 'Delete'))

    type = models.CharField(_('Type'), choices=TYPES, max_length=10)
    name = models.CharField(_('name'), max_length=30)
    permission = models.CharField(_('Permission'), max_length=50, unique=True)
    order = models.PositiveSmallIntegerField(_('Order'), default=1)

    class Meta:
        db_table = 'permission_label'
        verbose_name = _('Permission Label')
        verbose_name_plural = _('Permission Labels')
        unique_together = ('type', 'name')
        ordering = ('order',)


class Group(BaseModel):
    """
    Groups are a generic way of categorizing users to apply permissions, or
    some other label, to those users. A user can belong to any number of
    groups.

    A user in a group automatically has all the permissions granted to that
    group. For example, if the group 'Site editors' has the permission
    can_edit_home_page, any user in that group will have that permission.

    Beyond permissions, groups are a convenient way to categorize users to
    apply some label, or extended functionality, to them. For example, you
    could create a group 'Special users', and you could write code that would
    do special things to those users -- such as giving them access to a
    members-only portion of your site, or sending them members-only email
    messages.

    Account wise groups, and it's permissions. This can be considered as a special permission along with user's group
    based default permissions.
    This can be filtered by Account
    """
    name = models.CharField(_('name'), max_length=150)
    account = models.ForeignKey(Account, verbose_name=_('Account'), related_name='groups', on_delete=models.CASCADE)
    can_view = ArrayField(models.CharField(max_length=20, blank=True), blank=True, null=True)
    can_add = ArrayField(models.CharField(max_length=20, blank=True), blank=True, null=True)
    can_change = ArrayField(models.CharField(max_length=20, blank=True), blank=True, null=True)
    can_delete = ArrayField(models.CharField(max_length=20, blank=True), blank=True, null=True)
    can_approve = ArrayField(models.CharField(max_length=20, blank=True), blank=True, null=True)
    can_added_job = ArrayField(models.CharField(max_length=20, blank=True), blank=True, null=True)
    permissions = models.ManyToManyField(
        Permission,
        verbose_name=_('permissions'),
        blank=True,
        related_name='groups',
        related_query_name='custom_group'  # Do not change this name.
    )

    objects = GroupManager()

    class Meta:
        db_table = 'group'
        verbose_name = _('Group')
        verbose_name_plural = _('Groups')
        unique_together = ('name', 'account')
        ordering = ('name',)

    def __str__(self):
        return f'Account: {self.account.name} | {self.name}'


class UserPermissionsMixin(PermissionsMixin):
    groups = models.ManyToManyField(
        Group,
        verbose_name=_('groups'),
        blank=True,
        help_text=_(
            'The groups this user belongs to. A user will get all permissions '
            'granted to each of their groups.'
        ),
        related_name='users',
        related_query_name='user_permissions'  # Do not change this name.
    )

    class Meta:
        abstract = True

    def _get_user_permissions(self):
        return self.user_permissions.all()

    def _get_group_permissions(self):
        return Permission.objects.filter(**{'custom_group__user_permissions': self})

    def _get_permissions(self, obj, from_name):
        """
        Return the permissions of `user_obj` from `from_name`. `from_name` can
        be either "group" or "user" to return permissions from
        `_get_group_permissions` or `_get_user_permissions` respectively.
        """
        if not self.is_active or self.is_anonymous or obj is not None:
            return set()

        perm_cache_name = '_%s_perm_cache' % from_name
        if not hasattr(self, perm_cache_name):
            if self.is_superuser:
                perms = Permission.objects.all()
            else:
                perms = getattr(self, '_get_%s_permissions' % from_name)()
            perms = perms.values_list('content_type__app_label', 'codename').order_by()
            setattr(self, perm_cache_name, {"%s.%s" % (ct, name) for ct, name in perms})
        return getattr(self, perm_cache_name)

    def _get_all_permissions(self, obj=None):
        return {
            *self.get_user_permissions(obj=obj),
            *self.get_group_permissions(obj=obj),
        }

    def get_user_permissions(self, obj=None):
        """
        Return a set of permission strings the user `user_obj` has from their
        `user_permissions`.
        """
        return self._get_permissions(obj, 'user')

    def get_group_permissions(self, obj=None):
        """
        Return a set of permission strings the user `user_obj` has from the
        groups they belong.
        """
        return self._get_permissions(obj, 'group')

    def get_all_permissions(self, obj=None):
        if not self.is_active or self.is_anonymous or obj is not None:
            return set()
        if not hasattr(self, '_perm_cache'):
            self._perm_cache = self._get_all_permissions()
        return self._perm_cache


class UserManager(BaseUserManager):
    def _create_user(self, email, password=None, is_staff=False, is_superuser=False, **extra_fields):
        # if not email:
        #     raise ValueError('Users must have an email address')
        if email:
            email = self.normalize_email(email)
            user = self.model(
                email=email,
                is_staff=is_staff,
                is_superuser=is_superuser,
                **extra_fields
            )
        else:
            user = self.model(
                email=None,
                is_staff=is_staff,
                is_superuser=is_superuser,
                **extra_fields
            )

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save(using=self._db)
        return user

    def create_user(self, email, password, **extra_fields):
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        return self._create_user(email, password, True, True, **extra_fields)


class User(BaseModel, AbstractBaseUser, UserPermissionsMixin):
    CATEGORIES = (('Fyxt', 'Fyxt'), ('Customer', 'Customer'), ('Tenant', 'Tenant'), ('Vendor', 'Vendor'),
                  ('Owner Group', 'Owner Group'))
    TYPES = (('Owner', 'Owner'), ('Member', 'Member'), ('Manager', 'Manager'), ('Engineer', 'Engineer'))
    GENDERS = (('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other'))

    hubspot_id = models.BigIntegerField(verbose_name=_('HubSpot ID'), blank=True, null=True)
    crm_contact_id = models.UUIDField(_('CRM Contact ID'), editable=False, null=True, blank=True)
    accounts = models.ManyToManyField(Account, verbose_name=_('Accounts'), related_name='users')
    category = models.CharField(_('Category'), choices=CATEGORIES, max_length=25, default='Fyxt')
    types = ArrayField(models.CharField(choices=TYPES, max_length=25), default=list,
                       help_text=_('Use comma(,) separate to add multiple types.'))
    # #TODO this has to be a foreign key of group
    # role = models.CharField(_('Role'), choices=TYPES, max_length=25, null=True, blank=True)
    title = models.CharField(_('Title'), max_length=50, blank=True, null=True)
    email = models.EmailField(_('email'), unique=True, blank=True, null=True)
    recovery_email = models.EmailField(_('Recovery Email'), blank=True, null=True)
    phone = PhoneNumberField(_('Phone'), unique=False, blank=True, null=True)
    first_name = models.CharField(_('First Name'), max_length=255, blank=True)
    last_name = models.CharField(_('Last Name'), max_length=255, blank=True)
    gender = models.CharField(_('Gender'), choices=GENDERS, max_length=11, blank=True)
    photo = models.ImageField(_('User Image'), upload_to='profiles', blank=True, null=True)
    is_staff = models.BooleanField(_('Staff status'), default=False,
                                   help_text=_('Designates whether the user can log into this admin site.'))

    popup = models.BooleanField(default=False)  # Need to check the realtime usage of this.
    is_first_ticket_created = models.BooleanField(_('Is first ticket created?'), default=False)
    is_first_time_login = models.BooleanField(_('Is first time login?'), default=True)
    live = models.BooleanField(_('Live?'), default=False)

    notes = models.TextField(blank=True)

    is_suspended = models.BooleanField(_('Is suspended'), default=False)
    suspended_date = models.DateField(_('Suspended Date'), null=True, blank=True)

    password = models.CharField(_('password'), max_length=255, blank=True)
    is_send_first_email = models.BooleanField(_('is_send_email'), default=True)

    objects = UserManager()
    USERNAME_FIELD = 'email'
    EMAIL_FIELD = 'email'

    def __str__(self):
        return f'{self.full_name}[{self.email}]'

    class Meta:
        db_table = 'user'
        verbose_name = _('User')
        verbose_name_plural = _('Users')
        ordering = ('-created_at',)

    @property
    def token(self):
        return str(RefreshToken.for_user(self).access_token)

    @property
    def full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        return f'{self.first_name} {self.last_name}'.strip()

    @property
    def fullname(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        if not self.first_name:
            return f'Unknown [{self.email}]'

        return (
            f'{self.first_name} {self.last_name}'.strip()
            if self.last_name
            else f'{self.first_name}'.strip()
        )

    @property
    def group(self):
        return self.groups.filter(is_active=True).values_list('name', flat=True).first()

    def has_types(self, types):
        return any(_type in self.types for _type in types)

    @property
    def is_engineer_only(self):
        return True if 'Engineer' in self.types and len(self.types) == 1 else False

    @property
    def is_manager_only(self):
        return True if 'Manager' in self.types and len(self.types) == 1 else False

    def get_profile(self):
        from inbox.models import Mail
        from chat.models import ChatMember
        from notification.models import NotificationUser

        fields = ['id', 'category', 'types', 'first_name', 'last_name', 'title', 'email', 'recovery_email',
                  'is_suspended', 'is_active']
        data = {f: getattr(self, f) for f in fields}
        data.update({
            'phone': self.phone_dict if self.phone else None,
            'photo': self.photo.url if self.photo else None,
            'permissions': get_cleaned_permissions(self.get_all_permissions()),
            'settings': self.setting.to_dict(),
        })

        if 'add_mail' in data.get('permissions'):
            new_mail_qs = Mail.objects \
                .filter(conversation__read=False, mailbox__is_active=True, status__in=['Open', 'open']) \
                .order_by('-id') \
                .distinct('id') \
                .exclude(Q(type__in=['Spam', 'Trash']) | Q(status='Resolved'))

            data['new_mails'] = new_mail_qs.count()
        if self.category == 'Customer':
            data['new_chats'] = ChatMember.objects.filter(
                is_active=True, unread__gt=0, user=self.id
            ).count()

        data['new_jobs'] = self.get_new_jobs_count()

        data['new_notifications_count'] = NotificationUser.objects.filter(
            is_active=True, read=False, user=self
        ).count()
        return data

    def get_profile_web(self):
        data = self.get_profile()
        if 'Engineer' in self.types:
            try:
                data.update({
                    'engineer': self.profile.to_dict()
                })

                data['engineer'].update({
                    'address': self.company.address.to_dict() if self.company and self.company.address else {},
                    'properties': [{
                        'id': engineer.property.id,
                        'name': engineer.property.name,
                        'address': engineer.property.property_address.to_dict()
                    } for engineer in self.engineers.select_related('property').filter(is_active=True)]
                })

            except ObjectDoesNotExist:
                pass

        if self.category == 'Tenant':
            try:
                member = self.tenant_member
            except ObjectDoesNotExist:
                member = None

            if member:
                data.update({
                    'tenant': {
                        'id': member.tenant.id,
                        'can_create_job': member.tenant.can_create_job,
                        'can_schedule_own_service_dates': member.tenant.can_schedule_own_service_dates,
                        'can_view_vendor_library': member.tenant.can_view_vendor_library,
                        'can_view_lease_details': member.tenant.can_view_lease_details,
                        'properties': [{'id': val.property.id, 'name': val.property.name}
                                       for val in member.tenant.properties.select_related('property').
                                       filter(is_active=True)]
                    }
                })

        return data

    def get_profile_mobile(self):
        data = self.get_profile()
        if self.category == 'Tenant':
            try:
                member = self.tenant_member
            except ObjectDoesNotExist:
                member = None

            if member:
                data.update({
                    'tenant': {
                        'id': member.tenant.id,
                        'company': member.tenant.company.name,
                        'abstract': {
                            'name': member.tenant.abstract.name,
                            'type': member.tenant.abstract.type,
                            'lease_end_date': member.tenant.abstract.lease_end_date
                        },
                        'can_create_job': member.tenant.can_create_job,
                        'can_schedule_own_service_dates': member.tenant.can_schedule_own_service_dates,
                        'properties': [{'id': val.property.id, 'name': val.property.name}
                                       for val in member.tenant.properties.select_related('property').
                                       filter(is_active=True)]
                    }
                })
        return data

    def get_new_jobs_count(self):
        from job.models import Job

        if self.category == 'Customer':
            if 'Manager' in self.types:
                return Job.objects.filter(is_active=True, status='Created', responsible__in=['Manager', 'Both'],
                                          property__managers__user=self.id).count()
            else:
                return Job.objects.filter(is_active=True, status='Created', responsible__in=['Manager', 'Both']).count()

        elif self.category == 'Tenant':
            return Job.objects.filter(is_active=True, status='Created', responsible='Tenant').count()

        return 0

    @property
    def phone_dict(self):
        if self.phone:
            data = {
                'number': f'{self.phone.national_number}',
                'e164_number': self.phone.as_e164,
                'dial_code': f'+{self.phone.country_code}'
            }
            if self.phone.country_code == 1:
                data.update({'country_code': 'US'})
            else:
                data.update({'country_code': country.iso if (country := Country.objects.
                                                            filter(calling_code=self.phone.country_code).first()) else ''})

            return data
        else:
            return {}

    @property
    def account(self):
        if account := self.accounts.filter(is_active=True).first():
            return account
        return None

    @property
    def accounts_str(self):
        if accounts := self.accounts.filter(is_active=True):
            return ', '.join([account.name for account in accounts])
        return None

    @property
    def domain(self):
        if account := self.account:
            return account.domains.filter(is_active=True, is_primary=True).first()
        return None

    @property
    def invitation_link(self):
        if self.is_active:
            return 'Onboarded'
        elif domain := self.domain:
            with suppress(Exception):
                return f'{domain.origin}/onboard/{self.email_verification.token}/{self.category.lower()}/'
        return 'Invitation link is not found. Send invitation from Fyxt portal'

    @property
    def company(self):
        if self.category == 'Customer':
            if account := self.account:
                return account.company
        elif self.category == 'Tenant':
            try:
                return self.tenant_member.tenant.company
            except ObjectDoesNotExist:
                return None

        elif self.category == 'Vendor':
            try:
                return self.vendor_member.vendor.company
            except ObjectDoesNotExist:
                return None

        return None

    def short_profile_dict(self):
        return {
            'full_name': self.full_name,
            'photo': self.photo.url if self.photo else None
        }

    def short_dict(self):
        return {
            'id': self.id,
            'category': self.category,
            'full_name': self.full_name,
            'types': self.types,
            'photo': self.photo.url if self.photo else None,
            'company': self.company.name if self.company else None
        }

    def mail_dict(self):
        return {
            'id': self.id,
            'full_name': self.full_name,
            'email': self.email,
            'phone': self.phone.as_international,
            'photo': self.photo.url if self.photo else None,
        }

    def get_engineer(self):
        # Used in My Engineers page
        return {
            'id': self.id,
            'full_name': self.full_name,
            'email': self.email,
            'phone': self.phone.as_international,
            'properties': [engineer.property.name
                           for engineer in self.engineers.select_related('property').filter(is_active=True).
                           order_by('property__name')]
        }

    def contact_short(self):
        return {
            'id': self.id,
            'category': self.category,
            'types': self.types,
            'full_name': self.full_name,
            'email': self.email,
        }

    def contact(self):
        data = {
            'id': self.id,
            'category': self.category,
            'types': self.types,
            'full_name': self.full_name,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'phone': self.phone.as_international
        }

        if self.category == 'Tenant':
            data['tenant'] = {
                'type': 'Tenant',
                'id': self.tenant_member.tenant.id,
                'company': self.tenant_member.tenant.company.name,
                'primary_contact': self.tenant_member.tenant.primary_contact_dict(),
            }

        if self.category == 'Vendor':
            data['Vendor'] = {
                'type': 'Vendor',
                'id': self.vendor_member.vendor.id,
                'company': self.vendor_member.vendor.company.name,
                'primary_contact': self.vendor_member.vendor.primary_contact_dict(),
            }

        return data

    @transaction.atomic
    def save(self, *args, **kwargs):
        self.email = self.email.lower() if self.email else None
        return super(User, self).save(*args, **kwargs)


class Profile(BaseModel):
    TYPES = (('Engineer', 'Engineer'), ('Day Porter', 'Day Porter'))

    # This is only for engineers
    user = models.OneToOneField(User, verbose_name=_('User'), related_name='profile', on_delete=models.CASCADE)
    role = models.CharField(_('Engineer Role'), choices=TYPES, max_length=25, default='Engineer')
    hourly_rate = models.DecimalField(_('Standard Hourly Rate'), max_digits=12, decimal_places=2)
    overtime_charge = models.DecimalField(_('Overtime Charges'), max_digits=12, decimal_places=2)
    trip_charge = models.DecimalField(_('Trip Charges'), max_digits=12, decimal_places=2)
    weekend_rate = models.DecimalField(_('Weekend Rate'), max_digits=12, decimal_places=2)

    class Meta:
        db_table = 'profile'
        verbose_name = _('Profile')
        verbose_name_plural = _('Profiles')

    def __str__(self):
        return self.user.full_name

    def to_dict(self):
        fields = ['id', 'role', 'hourly_rate', 'overtime_charge', 'trip_charge', 'weekend_rate']
        data = {f: getattr(self, f) for f in fields}
        data['primary_contact'] = self.user.engineers.all()[0].primary_contact
        return data


class PhoneVerification(BaseModel):
    user = models.OneToOneField(User, verbose_name=_('User'), related_name='phone_verification',
                                on_delete=models.CASCADE, null=True, blank=True)
    otp = models.IntegerField(_('OTP'))
    is_verified = models.BooleanField(_('Is Verified?'), default=False)

    class Meta:
        db_table = 'phone_verification'
        verbose_name = _('Phone Verification')
        verbose_name_plural = _('Phone Verifications')

    def __str__(self):
        return f'{self.user.phone} - {self.otp}'

    def generate_otp(self, interval=300):
        # Default interval time is 5 Minute
        totp = pyotp.TOTP('JBSWY3DPEHPK3PXP', digits=4, interval=interval)
        self.otp = totp.now()
        self.save()
        return self.otp

    def sms_otp(self):
        self.generate_otp()
        msg = f'{self.otp} is your verification code for Fyxt. Please do not share this with anyone. ' \
              f'Fyxt will never call to confirm your verification code.'
        return sms.send(self.user.phone, msg)


class EmailVerification(BaseModel):
    user = models.OneToOneField(User, verbose_name=_('User'), related_name='email_verification',
                                on_delete=models.CASCADE)
    token = models.UUIDField(_('Token'), unique=True, db_index=True, default=uuid.uuid4, editable=False)
    is_verified = models.BooleanField(_('Is Verified?'), default=False)

    class Meta:
        db_table = 'email_verification'
        verbose_name = _('Email Verification')
        verbose_name_plural = _('Email Verifications')

    def __str__(self):
        return f'{self.user.email} - {self.is_verified}'


class UserSetting(BaseModel):
    user = models.OneToOneField(User, verbose_name=_('User'), related_name='setting', on_delete=models.CASCADE)
    email_notification_for_new_jobs = models.BooleanField(_('Receive email notifications for new jobs?'), default=True)
    email_notification_for_job_updates = models.BooleanField(_('Receive email notifications for job updates?'),
                                                             default=True)
    email_notification_for_new_messages = models.BooleanField(_('Receive email notifications for new messages?'),
                                                              default=True)
    email_notification_for_high_priority_job_over_due_by_two_days = models.BooleanField(_(
        'Receive email notifications for email notification high priority job is over due by two days?'), default=True)
    email_notification_for_job_overdue_by_one_week = models.BooleanField(_(
        'Receive email notifications for job is overdue by one week?'), default=True)
    email_notification_for_emergency_job_created = models.BooleanField(_(
        'Receive email notifications for emergency job is created?'), default=True)

    sms_notification_for_new_jobs = models.BooleanField(_('Receive SMS notifications for new jobs?'), default=True)
    sms_notification_for_job_updates = models.BooleanField(_('Receive SMS notifications for job updates?'),
                                                           default=True)
    sms_notification_for_new_messages = models.BooleanField(_('Receive SMS notifications for new messages?'),
                                                            default=True)
    sms_notification_for_high_priority_job_over_due_by_two_days = models.BooleanField(_(
        'Receive SMS notifications for email notification high priority job is over due by two days?'), default=True)
    sms_notification_for_job_overdue_by_one_week = models.BooleanField(_(
        'Receive SMS notifications for job is overdue by one week?'), default=True)
    sms_notification_for_emergency_job_created = models.BooleanField(_(
        'Receive SMS notifications for emergency job is created?'), default=True)

    push_notification_for_new_jobs = models.BooleanField(_('Receive push notifications for new jobs?'), default=True)
    push_notification_for_job_updates = models.BooleanField(_('Receive push notifications for job updates?'),
                                                            default=True)
    push_notification_for_new_messages = models.BooleanField(_('Receive push notifications for new messages?'),
                                                             default=True)
    push_notification_for_high_priority_job_over_due_by_two_days = models.BooleanField(_(
        'Receive push notifications for email notification high priority job is over due by two days?'), default=True)
    push_notification_for_job_overdue_by_one_week = models.BooleanField(_(
        'Receive push notifications for job is overdue by one week?'), default=True)
    push_notification_for_emergency_job_created = models.BooleanField(_(
        'Receive push notifications for emergency job is created?'), default=True)

    class Meta:
        db_table = 'user_settings'
        verbose_name = _('User Setting')
        verbose_name_plural = _('User Settings')

    def __str__(self):
        return self.user.full_name

    def to_dict(self):
        return {
            f: getattr(self, f)
            for f in [
                'id',
                'email_notification_for_new_jobs',
                'email_notification_for_job_updates',
                'email_notification_for_new_messages',
                'email_notification_for_high_priority_job_over_due_by_two_days',
                'email_notification_for_job_overdue_by_one_week',
                'email_notification_for_emergency_job_created',
                'sms_notification_for_new_jobs',
                'sms_notification_for_job_updates',
                'sms_notification_for_new_messages',
                'sms_notification_for_high_priority_job_over_due_by_two_days',
                'sms_notification_for_job_overdue_by_one_week',
                'sms_notification_for_emergency_job_created',
                'push_notification_for_new_jobs',
                'push_notification_for_job_updates',
                'push_notification_for_new_messages',
                'push_notification_for_high_priority_job_over_due_by_two_days',
                'push_notification_for_job_overdue_by_one_week',
                'push_notification_for_emergency_job_created'
            ]
        }


# Shared Models
class Owner(BaseModel):
    user = models.OneToOneField(User, verbose_name=_('User'), related_name='owner', on_delete=models.CASCADE,
                                help_text=_('POC'))
    company = models.ForeignKey(Company, verbose_name=_('Company'), related_name='owner', on_delete=models.CASCADE,
                                help_text=_('Entity'))

    class Meta:
        db_table = 'owner'
        verbose_name = _('Owner')
        verbose_name_plural = _('Owner')
        ordering = ('-created_at',)

    def __str__(self):
        return self.company.name

    def to_dict(self):
        return {
            'id': self.id,
            'company': {
                'name': self.company.name,
                'type': self.company.type,
                'ein': self.company.ein,
                'address': self.company.addresses.filter(type='Legal').first().to_dict()
            },
            'user': {
                'first_name': self.user.first_name,
                'last_name': self.user.last_name,
                'email': self.user.email,
                'phone': self.user.phone.as_international
            }
        }


# Email, SMS, Push Notifications Permissions to Account level users roles
class AccountsNotificationSetUp(BaseModel):
    account = models.OneToOneField(Account, verbose_name=_('Account'), related_name='notificationsetup',
                                   on_delete=models.CASCADE)

    pm_emails = models.BooleanField(_('Receive PM email notifications?'), default=True)
    pm_sms = models.BooleanField(_('Receive PM SMS notifications?'), default=True)
    pm_push = models.BooleanField(_('Receive PM Push notifications?'), default=True)

    tenant_emails = models.BooleanField(_('Receive Tenant email notifications?'), default=True)
    tenant_sms = models.BooleanField(_('Receive Tenant SMS notifications?'), default=True)
    tenant_push = models.BooleanField(_('Receive Tenant Push notifications?'), default=True)

    engineers_emails = models.BooleanField(_('Receive Engineers email notifications?'), default=True)
    engineers_sms = models.BooleanField(_('Receive Engineers sms notifications?'), default=True)
    engineers_push = models.BooleanField(_('Receive Engineers Push notifications?'), default=True)

    vendor_emails = models.BooleanField(_('Receive Vendor email notifications?'), default=True)
    vendor_sms = models.BooleanField(_('Receive Vendor SMS notifications?'), default=True)
    vendor_push = models.BooleanField(_('Receive Vendor Push notifications?'), default=True)

    user_invitation_email = models.BooleanField(_('Receive Invite New User Email notifications?'), default=True)

    class Meta:
        db_table = 'accounts_notification_setup'
        verbose_name = _('Accounts Notification SetUp')
        verbose_name_plural = _('Accounts Notification SetUps')

    def __str__(self):
        return self.account.name

    def to_dict(self):
        return {
            f: getattr(self, f)
            for f in [
                'id',
                'pm_emails',
                'pm_sms',
                'pm_push',
                'tenant_emails',
                'tenant_sms',
                'tenant_push',
                'engineers_emails',
                'engineers_sms',
                'engineers_push',
                'vendor_emails',
                'vendor_sms',
                'vendor_push',
                'user_invitation_email'
            ]
        }


class StandardView(BaseModel):
    view_name = models.CharField(_('View Name'), max_length=50)

    class Meta:
        abstract = True


class BaseView(StandardView):
    TYPES = (('Dashboard', 'Dashboard'),)

    default = models.BooleanField(_('Default'), default=True)
    is_pin = models.BooleanField(_('Is Pin'), default=False)
    type = models.CharField(_('App Name'), choices=TYPES, max_length=25, default='Dashboard')

    def __str__(self):
        return self.view_name

    class Meta:
        db_table = 'base_view'
        verbose_name = _('Base View')
        verbose_name_plural = _('Base Views')
        ordering = ('-created_at',)


class UserView(StandardView):
    user = models.ForeignKey(User, verbose_name=_('User'), related_name='user_views', related_query_name='user_view',
                             on_delete=models.CASCADE)
    is_private = models.BooleanField(_('Is Private'), default=False)
    is_standard = models.BooleanField(_('Is Standard View'), default=False)
    view_type = models.CharField(_('Type of View'), max_length=25, null=True, blank=True)
    make_as_default = models.BooleanField(_('Make As Default'), default=False)
    is_pin = models.BooleanField(_('Is Pin'), default=False)
    current_active_tab = models.BooleanField(_('Current Active Tab'), default=False)
    query = models.JSONField(_('Query'), null=True, blank=True)

    def __str__(self):
        return self.view_name

    class Meta:
        db_table = 'user_view'
        verbose_name = _('User View')
        verbose_name_plural = _('User Views')
        ordering = ('-created_at',)


class StandardColumn(BaseModel):
    COLUMNS = (('Job ID', 'Job ID'), ('Property', 'Property'), ('Brief Description', 'Brief Description'),
               ('Category', 'Category'), ('Priority', 'Priority'), ('Actions', 'Actions'),
               ('Service Location', 'Service Location'), ('Assigned Managers', 'Assigned Managers'),
               ('Assigned Engineers', 'Assigned Engineers'), ('Date Created', 'Date Created'), ('Status', 'Status'),
               ('Service Type', 'Service Type'), ('Linked Jobs', 'Linked Jobs'), ('Source Type', 'Source Type'),
               ('Target Completion Date', 'Target Completion Date'), ('Associated Emails', 'Associated Emails'),
               ('Last Activity', 'Last Activity'), ('Vendor(s)', 'Vendor(s)'), ('Followers', 'Followers'),
               ('Tenant', 'Tenant'), ('Tenant Contact', 'Tenant Contact'), ('Billable Party', 'Billable Party'),
               ('Assigned To', 'Assigned To'))

    column_name = models.CharField(_('Column Name'), choices=COLUMNS, max_length=25)

    class Meta:
        abstract = True


class BaseColumn(StandardColumn):
    default = models.BooleanField(_('Default'), default=True)
    is_select = models.BooleanField(_('Is Select'), default=False)

    def __str__(self):
        return self.column_name

    class Meta:
        db_table = 'base_column'
        verbose_name = _('Base Column')
        verbose_name_plural = _('Base Columns')
        ordering = ('-created_at',)


class UserColumn(StandardColumn):
    view = models.ForeignKey(UserView, verbose_name=_('View'), related_name='user_columns',
                             related_query_name='user_column', on_delete=models.CASCADE)
    order = models.PositiveSmallIntegerField(_('Order'))
    custom = models.JSONField(_('Custom'), blank=True, null=True)
    is_select = models.BooleanField(_('Is Select'), default=False)

    def __str__(self):
        return self.column_name

    class Meta:
        db_table = 'user_column'
        verbose_name = _('User Column')
        verbose_name_plural = _('User Columns')
        ordering = ('order',)


class CompanyContactType(BaseModel):
    '''
    This model contains type for company, contact, phone, email, and address
    This table will be controlled by Fyxt admin from Django admin
    '''

    CATEGORIES = (('Company', 'Company'), ('Contact', 'Contact'), ('CompanyEmail', 'CompanyEmail'), ('CompanyPhone', 'CompanyPhone'),
                  ('Address', 'Address'), ('ContactEmail', 'ContactEmail'), ('ContactPhone', 'ContactPhone'))

    name = models.CharField(_('Name'), max_length=255)
    category = models.CharField(_('Category'), choices=CATEGORIES, max_length=25,
                                help_text='Use the category dropdown based on your requirements. For example, use the phone category for the phone dropdown.')
    order = models.PositiveSmallIntegerField(_('Order'))

    class Meta:
        db_table = 'company_contact_type'
        unique_together = ('name', 'category')
        verbose_name = _('Company Contact Type')
        verbose_name_plural = _('Company Contact Types')
        ordering = ('order',)
