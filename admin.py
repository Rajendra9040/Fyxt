from django.contrib import admin

# Register your models here.
from . models import (
    Chart, ChartUpload,
)


class ChartAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'batch_id', 'chart_id', 'upload_date', 'client', 'specialty', 'status', 'total_pages', 'last_updated_date', 'auditor', 'qa', 
        'upload_chart', 'offline_upload_flag', 'urgent_flag', 'audited_date', 'archived_date', 'rebuttal_date', 'is_split',
        'chart_updated_date', 'is_deleted'
    )
    list_filter = ('batch_id', 'auditor', 'qa', 'client', 'status', 'is_deleted', 'urgent_flag', 'is_split')
    
    model = Chart
admin.site.register(Chart, ChartAdmin)


class ChartUploadAdmin(admin.ModelAdmin):
    list_display = ('id', 'client', 'uploaded_date', 'upload_chart', 'total_pages')
    model = ChartUpload

admin.site.register(ChartUpload, ChartUploadAdmin)