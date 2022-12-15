from cqusers.models import CqUser
from .models import AuditSheet, AuditHoursMonitor, AuditSheetComment, Industry, AuditSheetMetric, CqUser
from rest_framework import serializers
from cqclient.models import HealthSystem, Hospital, Department
from cqdashboard.models import Chart



class AuditSheetSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        result = {
            #"index" : instance.index,
            #"sheet_name" : instance.sheet_name,
            "file_name" : instance.chart_id.chart_id,
            "chart_id" : instance.chart_id.id,
            'id': instance.id,
            'row_id': instance.row_id,
            "encounter_no" : instance.encounter_no,
            "rendering" : {"id":instance.rendering.id, "first_name": instance.rendering.user.first_name, "last_name":instance.rendering.user.last_name}  if instance.rendering else None,
            "enc_dt" : instance.enc_dt,
            "srvcs_no" : instance.srvcs_no,
            "provider_rvu" : instance.provider_rvu,
            "provider_dollar_value" : instance.provider_dollar_value,
            "response" : instance.response,
            "agree" : instance.agree,
            "disagree" : instance.disagree,
            "audited_code" : instance.audited_code,
            "audited_rvu" : instance.audited_rvu,
            "audited_dollar_value" : instance.audited_dollar_value,
            "notes" : instance.notes,
        }
        return result 

    class Meta:
        model = AuditSheet
        fields = "__all__"


class RecentAuditsSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        result = {}

        chart = Chart.objects.get(id=instance['chart_id'])
        auditor_hours_moniter = AuditHoursMonitor.objects.filter(user=instance['user'], chart_id=chart.id).last()
        result['id'] = chart.id
        result['chart_id'] = chart.chart_id
        result['user'] = auditor_hours_moniter.user.id
        result['audit_start_time'] = auditor_hours_moniter.audit_start_time
        result['audit_end_time'] = auditor_hours_moniter.audit_end_time
        result['recent_audit_snaps'] = auditor_hours_moniter.recent_audit_snaps.url if auditor_hours_moniter.recent_audit_snaps else None
        return result

    class Meta:
        model = AuditHoursMonitor
        fields = "__all__"


class AuditHoursMonitorSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        result = {}
        result['id'] = instance.chart_id.id
        result['chart_id'] = instance.chart_id.chart_id
        result['user'] = instance.user.id
        result['audit_start_time'] = instance.audit_start_time
        result['audit_end_time'] = instance.audit_end_time
        result['recent_audit_snaps'] = instance.recent_audit_snaps.url if instance.recent_audit_snaps else "NA"

    class Meta:
        model = AuditHoursMonitor
        fields = "__all__"


class IndustrySerializer(serializers.ModelSerializer):

    class Meta:
        model = Industry
        fields = "__all__"


class AuditSheetMetricSerializer(serializers.ModelSerializer):

    class Meta:
        model = AuditSheetMetric
        fields = "__all__"


class AuditorDropdownSerializer(serializers.ModelSerializer):

    class Meta:
        model = CqUser
        fields = ('id', 'first_name', 'last_name', 'role')


class AuditSheetCommentSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        result = {}
        result['id'] = instance.id
        result['chart'] = instance.chart.id
        result['file_name'] = instance.chart.chart_id 
        result['parent'] = instance.parent.id if instance.parent  else None
        result['audit_sheet_rows'] = instance.audit_sheet_rows
        result['audit_sheet_columns'] = instance.audit_sheet_columns
        result['user'] = {"id":instance.user.id, "first_name":instance.user.first_name, "last_name":instance.user.last_name}
        result['tagged_user'] = instance.tagged_user
        result['comment'] = instance.comment
        result['action'] = instance.action
        result['commented_date'] = instance.updated_at
        result['reply_comments'] =[{
            "id": comment.id,
            "chart": comment.chart_id,
            "file_name": comment.chart.chart_id,
            "parent": comment.parent.id if comment.parent  else None, 
            "audit_sheet_rows": comment.audit_sheet_rows, 
            "audit_sheet_columns": comment.audit_sheet_columns, 
            "user":{"id": comment.user.id, "first_name":comment.user.first_name, "last_name":comment.user.last_name},
            "tagged_user": comment.tagged_user, 
            "comment": comment.comment,
            "action": comment.action, 
            "commented_date": comment.updated_at
             }  for comment in instance.auditsheet_comment.all()]
        return result

    class Meta:
        model = AuditSheetComment
        fields = "__all__"


class AuditSheetHealthSystemSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        result = {}

        if self.context['request'].query_params.get('health_system_id'):
            result['id'] = instance.id
            result['name'] = instance.specialty.name

        if self.context['request'].query_params.get('hospital_id'):
            result['id'] = instance.id
            result['name'] = instance.specialty.name

        else:
            result['id'] = instance.id
            result['name'] = instance.name

        return result

    class Meta:
        model = HealthSystem


class AuditSheetHospitalSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        result = {}

        if self.context['request'].query_params.get('health_system_id'):
            result['id'] = instance.id
            # To get table name of the instance - instance._meta.db_table 
            if instance._meta.db_table == 'health_system':
                result['name'] = instance.name
            else:
                result['name'] = instance.specialty.name

        if self.context['request'].query_params.get('hospital_id'):
            result['id'] = instance.id
            result['name'] = instance.specialty.name

        else:
            result['id'] = instance.id
            result['name'] = instance.name

        return result

    class Meta:
        model = Hospital


class AuditSheetDepartmentSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        result = {}

        if self.context['request'].query_params.get('health_system_id'):
            result['id'] = instance.id
            # To get table name of the instance - instance._meta.db_table 
            if instance._meta.db_table == 'health_system':
                result['name'] = instance.name
            else:
                result['name'] = instance.specialty.name

        if self.context['request'].query_params.get('hospital_id'):
            result['id'] = instance.id
            result['name'] = instance.specialty.name

        else:
            result['id'] = instance.id
            result['name'] = instance.specialty.name

        return result

    class Meta:
        model = Department


class ListUsersSerializer(serializers.ModelSerializer):

    class Meta:
        model = CqUser
        fields = ('id', 'first_name', 'last_name','email', 'role')