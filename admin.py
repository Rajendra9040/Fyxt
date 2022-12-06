from django.contrib import admin
from .models import *

# Register your models here.

class AuditSheetAdmin(admin.ModelAdmin):

    list_display = [field.name for field in AuditSheet._meta.get_fields()]
    list_per_page = 20
    model = AuditSheet

admin.site.register(AuditSheet, AuditSheetAdmin)


class AuditHoursMonitorAdmin(admin.ModelAdmin):
    list_display = ('id', 'chart_id', 'user', 'recent_audit_snaps', 'audit_start_time', 'audit_end_time')
    model = AuditHoursMonitor

admin.site.register(AuditHoursMonitor, AuditHoursMonitorAdmin)


class IndustrtAdmin(admin.ModelAdmin):
    list_display =  [field.name for field in Industry._meta.get_fields()]

admin.site.register(Industry, IndustrtAdmin)


class AuditSheetMetricAdmin(admin.ModelAdmin):
    list_display =  [field.name for field in AuditSheetMetric._meta.get_fields()]

admin.site.register(AuditSheetMetric, AuditSheetMetricAdmin)


class AuditSheetCommentAdmin(admin.ModelAdmin):
    list_display =  ['id', 'chart', 'parent' , 'audit_sheet_rows', 'audit_sheet_columns', 'user', 'tagged_user', 'comment', 'commented_at', 'updated_at', 'action',]

admin.site.register(AuditSheetComment, AuditSheetCommentAdmin)