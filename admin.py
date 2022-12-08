from django.contrib import admin

# Register your models here.

from . models import *



class CQUserAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'email', 'first_name', 'last_name', 'role', 'is_active', 'is_deleted', 'created_date', 'updated_date', 'last_login', 'date_joined'
    )
    exclude = ('password',)
    model = CqUser

admin.site.register(CqUser, CQUserAdmin)


class SpecialtyAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'users', 'type')
    list_filter = ('type',)
    model = Specialty

    def users(self, obj):
        return " - ".join([f"{user.email} ({user.role})" for user in obj.cqusers.all()])

admin.site.register(Specialty, SpecialtyAdmin)


class CqTeamAdmin(admin.ModelAdmin):

    list_display = ('id', 'name', 'members_list', 'specialties_list', 'is_active')
    model = CqTeam

    def members_list(self, obj):
        return " - ".join([f"{user.email} ({user.role})" for user in obj.members.all()])

    def specialties_list(self, obj):
        return " - ".join([f"{specialty.name}" for specialty in obj.specialties.all()])

admin.site.register(CqTeam, CqTeamAdmin)


class FAQAdmin(admin.ModelAdmin):
    list_display = ('question', 'answer', 'is_active', 'order' , 'created_at', 'updated_at')
    model = FAQ

admin.site.register(FAQ, FAQAdmin)


class NotificationAdmin(admin.ModelAdmin):
    list_display = ('message', 'sender', 'type', 'created_at', 'is_active', 'reference_chart')
    model = Notification

admin.site.register(Notification, NotificationAdmin)


class NotificationUserAdmin(admin.ModelAdmin):
    list_display = ('user', 'notification', 'read')
    model = NotificationUser

admin.site.register(NotificationUser, NotificationUserAdmin)