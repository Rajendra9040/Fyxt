import magic
from datetime import datetime, timedelta

from django.utils import timezone
from django.db.models import Avg, Q, F, Sum

from rest_framework import serializers

from cqdashboard.models import *

from cqusers.tasks import sizeof_fmt
from cqusers.models import CqTeam

from cqclient.models import  Department, HealthSystem, Hospital, Insurance, Ehr
from cqclient.utils import get_health_system_clients, get_hospital_clients, get_department_clients, get_providers_clients

from auditsheet.models import AuditSheet, AuditSheetMetric, AuditHoursMonitor



def calulate_avg_completion_time(users):
    avg_completion_time = AuditHoursMonitor.objects.filter(user__in=users).annotate(duration=F('audit_end_time') - F('audit_start_time')).exclude(duration='00:00:00').aggregate(Avg('duration'))['duration__avg']
    if avg_completion_time:
        avg_completion_time /= timedelta(hours=1)
    else:
        avg_completion_time = 0
    return avg_completion_time


class ManagerDashboardSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        response = super().to_representation(instance)

        result = {}
        result['id'] = instance.id
        result['upload_id'] = instance.chart_id
        result['uploaded_date'] = instance.upload_date
        result['updated_date'] = instance.chart_updated_date
        result['archived_date'] = instance.archived_date

        # To get sepcialty/department based on hospital_id:
        if instance.client.user_type == "HEALTH SYSTEM":
            # TODO::
            # hospital_id = instance.client.health_system_client.first().hospital_health_system.all().values_list("id", flat=True)
            hospital_id = None
        elif instance.client.user_type in ["HOSPITAL", "PHYSICIANS GROUP"]:
            hospital_id = Hospital.objects.filter(is_active=True, is_deleted=False, spoc=instance.client)
        elif instance.client.user_type == "DEPARTMENT":
            hospital_id = Department.objects.filter(is_active=True, is_deleted=False, spoc=instance.client).values_list('hospital_id', flat=True)
        elif instance.client.user_type == "PROVIDER":
            hospital_id = Department.objects.filter(is_active=True, is_deleted=False, providers=instance.client).values_list('hospital_id', flat=True)

        if hospital_id:
            departments = Department.objects.filter(hospital__in=hospital_id, is_active=True, is_deleted=False)

        result['client_name'] = {
            'id': instance.client.user.id,
            'first_name': instance.client.user.first_name,
            'last_name': instance.client.user.last_name,
            'specialties': [{"id":dept_.specialty.id,  "name": dept_.specialty.name } for dept_ in departments] if hospital_id else []
        }

        if instance.specialty:
            result['specialties'] = {
                'id': instance.specialty.id,
                'name': instance.specialty.name
            }

        result['total_page'] = instance.total_pages
        result['status'] = instance.status
        result['urgent'] = instance.urgent_flag
        result['audited_date'] = instance.audited_date 

        if instance.auditor:
            result['assigned_auditor'] = {
                'id': instance.auditor.id,
                'first_name': instance.auditor.first_name,
                'last_name': instance.auditor.last_name
            }

        if instance.qa:
            result['assigned_qa'] = {
                'id': instance.qa.id,
                'first_name': instance.qa.first_name,
                'last_name': instance.qa.last_name
            }

        if instance.batch_id is None:
            result['is_splitted'] = True

        try:
            size = sizeof_fmt(instance.upload_chart.size)
            mime_type =  magic.from_buffer(instance.upload_chart.read(1024), mime=True)
            url = instance.upload_chart.url
        except:
            size = "0 KB"
            mime_type = f"application/{instance.upload_chart.name.split('.')[-1]}"
            url = ""

        result['file_obj'] = {
            'id': None,
            'name': instance.upload_chart.name,
            # 'size': f"{str(round(instance.upload_chart.size / (1024 * 1024), 2))} MB",
            # 'size1' : f"{math.ceil(instance.upload_chart.size / (1024 * 1024)) } MB",
            # 'size2' : f"{instance.upload_chart.size / (1024 * 1024)} MB",
            'size': size,
            'mime_type': mime_type,
            'preview_url': url
        }

        return result

    class Meta:
        model = Chart
        fields = '__all__'


class ManagerChartUploadSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        result = {}
        result['file_obj'] = {}
        result['file_obj']['id'] = instance.id
        result['file_obj']['name'] = instance.upload_chart.name
        # result['file_obj']['size'] =  f"{str(round(instance.upload_chart.size / (1024 * 1024), 2))} MB"
        # result['file_obj']['size1'] = f"{math.ceil(instance.upload_chart.size / (1024 * 1024)) } MB"
        # result['file_obj']['size2'] = f"{instance.upload_chart.size / (1024 * 1024)} MB"
        result['file_obj']['size'] = sizeof_fmt(instance.upload_chart.size),
        result['file_obj']['mime_type'] = magic.from_buffer(instance.upload_chart.read(1024), mime=True)
        result['file_obj']['preview_url'] = instance.upload_chart.url
        return result

    class Meta:
        model = ChartUpload
        fields = '__all__'


class SplitAuditSerializer(serializers.ModelSerializer):

    class Meta:
        model = Chart
        fields = ('chart_id', 'page_number_from', 'page_number_to', 'specialty', 'auditor')


class TeamMemberSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        all_charts = Chart.objects.filter(is_deleted=False, is_split=False)
        result = []
        for member_ in instance.filter(is_active=True, is_deleted=False):
            member_charts = all_charts.filter(Q(auditor=CqUser.objects.get(id=member_.id)) | Q(qa=CqUser.objects.get(id=member_.id)))
            result.append(
                {
                "id": member_.id,
                "email": member_.email,
                "first_name": member_.first_name,
                "last_name": member_.last_name,
                "role": member_.role,
                "open_rebutals": member_charts.filter(status__in=['QA REBUTTAL','CLIENT REBUTTAL']).count(),
                "active_audits": member_charts.filter(status__in=['AWAITING REVIEW','IN REVIEW','AWAITING AUDIT','IN PROGRESS', 'ON HOLD']).count(),
                "total_audits": member_charts.count(),  
                "completed": member_charts.filter(status__in=['ARCHIVED']).count()
            })

        return result

    class Meta:
        model = CqUser


class TeamDashboardSerializer(serializers.ModelSerializer):
    members = TeamMemberSerializer(read_only=True)
    open_rebutals = serializers.SerializerMethodField()
    active_audits = serializers.SerializerMethodField()
    total_audits = serializers.SerializerMethodField()
    completed = serializers.SerializerMethodField()
    last_90_assigned = serializers.SerializerMethodField()
    avg_completion_time = serializers.SerializerMethodField()
    total_charts = Chart.objects.filter(is_deleted=False, is_split=False)

    def team_members(self, instance):
        team_members = [members['id'] for members in instance.members.filter(is_active=True, is_deleted=False).values('id')]
        return team_members
        # return Chart.objects.filter(auditor__in=instance.members.filter(is_active=True, is_deleted=False), qa__in=instance.members.filter(is_active=True, is_deleted=False))
    def get_open_rebutals(self, instance):
        users = self.team_members(instance)
        open_rebutals = self.total_charts.filter(Q(auditor__in=users) | Q(qa__in=users)).filter(status__in=['QA REBUTTAL','CLIENT REBUTTAL']).count()
        return open_rebutals

    def get_active_audits(self, instance):
        users = self.team_members(instance)
        active_audits = self.total_charts.filter(Q(auditor__in=users) | Q(qa__in=users)).filter(status__in=['AWAITING REVIEW','IN REVIEW','AWAITING AUDIT','IN PROGRESS', "ON HOLD"]).count()
        return active_audits

    def get_total_audits(self, instance):
        users = self.team_members(instance)
        total_audits = self.total_charts.filter(Q(auditor__in=users) | Q(qa__in=users)).count()
        return total_audits

    def get_completed(self, instance):
        users = self.team_members(instance)
        completed = self.total_charts.filter(Q(auditor__in=users) | Q(qa__in=users)).filter(status__in=['ARCHIVED']).count()
        return completed

    def get_last_90_assigned(self, instance):
        users = self.team_members(instance)
        end_date = timezone.now()
        start_date = timezone.now()-timedelta(days=90)
        last_90_assigned_count = ChartHistory.objects.filter(user__in = users, chart__is_deleted = False, assigned_date__range = [start_date, end_date]).count()
        return last_90_assigned_count

    def get_avg_completion_time(self, instance):
        return f"{round(calulate_avg_completion_time(instance.members.all()), 2)} hrs"

    class Meta:
        model = CqTeam
        fields = ('id', 'name', 'members', 'specialties', 'open_rebutals', 'active_audits', 'total_audits', 'completed', 'last_90_assigned', 'avg_completion_time',)


class TeamSerializer(serializers.ModelSerializer):
    
    class Meta:
        model =CqTeam
        fields = "__all__"


class AuditHoursMonitorSerializer(serializers.ModelSerializer):

    class Meta:
        model = AuditHoursMonitor
        fields = "__all__"


class HealthSystemSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        result = {}
        result['id'] = instance.id
        result['name'] = instance.name
        result['prefix'] = instance.prefix
        result['type'] = instance.type
        result['address'] = instance.address
        
        result['specialty'] = [{"id": specialty['specialty__id'], "name": specialty['specialty__name']}
                            for specialty in instance.hospital_health_system.filter(is_deleted=False).values('specialty__id', 'specialty__name').filter(~Q(specialty__id=None)).distinct()]

        result['insurance'] = [{"id": insurance.id, "name": insurance.name} 
                            for insurance in instance.insurance.all()]

        result['ehr'] = [{"id": ehr.id, "name": ehr.name}
                        for ehr in instance.ehr.all()]

        result['account_contacts'] = [
            {"id": spoc.user.id, "first_name": spoc.user.first_name, 
            "last_name": spoc.user.last_name, "email": spoc.email, "is_primary":spoc.is_primary, "is_active": spoc.user.is_active} 
            for spoc in instance.spoc.all()]

        # To get the Client related to health_system and hospital:
        client_ids = get_health_system_clients(instance.id)
        if client_ids:
            # client_user_ids = [user_.id for user_ in CqUser.objects.filter(id__in=list(client_ids), is_active=True, is_deleted=False)]
            client_user_ids = [user_.id for user_ in CqUser.objects.filter(id__in=list(client_ids), is_deleted=False)]
            result['active_audits'] = Chart.objects.filter(Q(client__user_id__in=client_user_ids) & Q(is_split=False) & Q(is_deleted=False) & ~Q(batch_id=None) & ~Q(status="ARCHIVED")).count()
            result['total_audits'] = Chart.objects.filter(Q(client__user_id__in=client_user_ids) & Q(is_split=False) & Q(is_deleted=False) & ~Q(batch_id=None)).count()

        result["hospitals"] = [{"id": hospital.id, "name": hospital.name} for hospital in instance.hospital_health_system.filter(is_deleted=False)]
        result['is_active'] = instance.is_active
        result['is_deleted'] = instance.is_deleted

        return result

    class Meta:
        model = HealthSystem
        fields = "__all__"


class HealthSystemMembersSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):

        result = {}
        result['id'] = instance.client.user.id
        result['first_name'] = instance.client.user.first_name
        result['last_name'] = instance.client.user.last_name
        result['email'] = instance.client.user.email
        result['user_type'] = instance.client.user_type
        result['is_active'] = instance.client.user.is_active
        return result

    class Meta:
        model = Chart


class HealthSystemHospitalSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):

        result = {}
        result['id'] = instance.id
        result['name'] = instance.name

        # client_user_ids = get_hospital_clients(instance.health_system.id)
        client_user_ids = get_hospital_clients(instance.id)
        result['active_audits'] = Chart.objects.filter(Q(client__user_id__in=client_user_ids, is_split=False, is_deleted=False) & ~Q(batch_id=None) & ~Q(status__in=["ARCHIVED", "CLIENT REBUTTAL"])).count()

        # To Calculate Chart Accuracy and cq_rev_opp:
        charts = Chart.objects.filter(is_deleted=False, client__user__id__in=client_user_ids)
        audit_metrics = AuditSheetMetric.objects.filter(chart_id__in=charts).aggregate(Avg('cq_score'), Sum('outstanding_revenue'))
        result["chart_accuracy"] = round(audit_metrics['cq_score__avg'] or 0)
        result["cq_rev_opp"] = round(audit_metrics['outstanding_revenue__sum'] or 0, 2)
        return result
                  
    class Meta:
        model = Hospital


class HealthSystemHospitalDepartmentSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):

        result = {}
        result['id'] = instance.id
        result['name'] = instance.specialty.name

        client_user_ids = get_hospital_clients(instance.hospital.id)
        result['active_audits'] = Chart.objects.filter(Q(client__user_id__in=client_user_ids, specialty=instance.specialty, is_split=False, is_deleted=False) & ~Q(batch_id=None) & ~Q(status__in=["ARCHIVED", "CLIENT REBUTTAL"])).count()

        # To Calculate Chart Accurancy & cq_rev_opp:        
        charts = Chart.objects.filter(is_deleted=False, client__user__id__in=client_user_ids, specialty=instance.specialty)
        audit_metrics = AuditSheetMetric.objects.filter(chart_id__in=charts).aggregate(Avg('cq_score'), Sum('outstanding_revenue'))
        result["chart_accuracy"] = round(audit_metrics['cq_score__avg'] or 0)
        result["cq_rev_opp"] = round(audit_metrics['outstanding_revenue__sum'] or 0, 2)
        return result

    class Meta:
        model = Department


class HealthSystemHospitalProvidersSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):

        result = {}
        result['id'] = instance.id
        result['name'] = instance.specialty.name

        client_user_ids = get_providers_clients(instance.id)
        # client_user_ids = get_department_clients(instance.hospital.health_system.id)
        result['active_audits'] = Chart.objects.filter(Q(client__user_id__in=client_user_ids, is_split=False, is_deleted=False) & ~Q(batch_id=None) & ~Q(status__in=["ARCHIVED", "CLIENT REBUTTAL"])).count()

        # To Calculate Chart Accurancy:
        chart_ids = set([chart.id for chart in Chart.objects.filter(Q(client__user_id__in=client_user_ids) & Q(is_split=False) & Q(is_deleted=False) & ~Q(batch_id=None) & Q(status__in=["ARCHIVED", "CLIENT REBUTTAL"]))])
        chart_accuracy = AuditSheetMetric.objects.filter(chart_id__in=list(chart_ids)).aggregate(Avg('cq_score'))['cq_score__avg']
        result["chart_accuracy"] = round(chart_accuracy, 2) if chart_accuracy else 0

        # To Calculate cq_rev_opp:
        cq_rev_opp = AuditSheetMetric.objects.filter(chart_id__in=list(chart_ids)).aggregate(Sum("outstanding_revenue")).get("outstanding_revenue__sum")
        result["cq_rev_opp"] = round(cq_rev_opp, 2) if cq_rev_opp else None
        return result

    class Meta:
        model = Department


class HealthSystemTeamStatisticsSerializer(serializers.ModelSerializer):

    def chart_queryset(self, instance):
        return Chart.objects.filter(is_deleted=False) # Q(is_split=False) & ~Q(batch_id=None))

    def to_representation(self, instance):

        result = {}
        result['id'] = instance.id

        if self.context['request'].query_params.get('health_system_id'):
            result['name'] = instance.name
            client_ids = get_health_system_clients(instance.id)

        elif self.context['request'].query_params.get('hospital_id'):
            result['name'] = instance.name
            client_ids = get_hospital_clients(instance.id)

        elif self.context['request'].query_params.get('department_id'):
            result['name'] = instance.specialty.name
            client_ids = get_department_clients(instance.id)

        elif self.context['request'].query_params.get('provider_id'):
            result['name'] = instance.specialty.name
            client_ids = get_providers_clients(instance.id)

        client_user_ids = [user_.id for user_ in CqUser.objects.filter(id__in=list(client_ids), is_active=True, is_deleted=False)]
        result['total_audits'] = self.chart_queryset(instance).filter(client__user_id__in=client_user_ids).count()
        result['in_progress'] = self.chart_queryset(instance).filter(client__user_id__in=client_user_ids, status__in=['AWAITING REVIEW','IN REVIEW','AWAITING AUDIT','IN PROGRESS', 'AWAITING ASSIGNMENT', 'ON HOLD']).count()
        result['completed'] = self.chart_queryset(instance).filter(client__user_id__in=client_user_ids, status="ARCHIVED").count()
        result['open_rebuttals'] = self.chart_queryset(instance).filter(client__user_id__in=client_user_ids, status__in=['QA REBUTTAL','CLIENT REBUTTAL']).count()

        return result

    class Meta:
        model = HealthSystem


class HospitalAccountsSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        result = {}
        result['id'] = instance.id
        result['name'] = instance.name
        result['address'] = instance.address
        result['patients_per_month'] = instance.patients_per_month
        result['health_system'] = instance.health_system.id
        result['prefix'] = instance.health_system.prefix if instance.health_system.prefix else "CHPRE"
        result['department'] = [{"id": department.id, "name": department.specialty.name} 
                            for department in instance.department_hospital.filter(is_deleted=False)]

        result['insurance'] = [{"id": insurance.id, "name": insurance.name} 
                            for insurance in instance.insurance.all()]

        result['ehr'] = [{"id": ehr.id, "name": ehr.name}
                        for ehr in instance.ehr.all()]

        result['specialty'] = [{"id": department.specialty.id, "name": department.specialty.name}
                            for department in instance.department_hospital.filter(is_deleted=False)]

        result['account_contacts'] = [
            {"id": spoc.user.id, "first_name": spoc.user.first_name, 
            "last_name": spoc.user.last_name, "email": spoc.email, "is_primary":spoc.is_primary} 
            for spoc in instance.spoc.all()]

        result['is_active'] = instance.is_active
        return result

    class Meta:
        model = Hospital
        fields = "__all__"


class DepartmentSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        result = {}
        result['id'] = instance.id
        result['name'] = instance.specialty.name
        result['address'] = instance.hospital.address if instance.hospital else None
        result['patients_per_month'] = instance.hospital.patients_per_month if instance.hospital else None
        # result['physician'] = [{"id":provider.id, "first_name":provider.user.first_name, "last_name":provider.user.last_name} for provider in instance.providers.all()]
        if instance.hospital:
            result['insurance'] = [
                {"id": insurance.id, "name": insurance.name} 
                for insurance in instance.hospital.insurance.all() 
                ]

            result['ehr'] = [
                {"id": ehr.id, "name": ehr.name} 
                for ehr in instance.hospital.ehr.all() if instance.hospital
                ]
        else:
            result['insurance'] = None
            result['ehr'] = None

        result['account_contacts'] = [
        {'id': spoc_['user__id'], 'email': spoc_['user__email'], 'first_name': spoc_['user__first_name'], 'last_name': spoc_['user__last_name'], 'is_primary': spoc_['user__client__is_primary']} 
        for spoc_ in instance.spoc.values('user__id', 'user__email', 'user__first_name', 'user__last_name', 'user__client__is_primary')
        ]

        result['is_active'] = instance.is_active
        return result

    class Meta:

        model = Department
        fields = "__all__"

class ProviderSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        result = {}
        result["id"] = instance.id
        result["first_name"] = instance.user.first_name
        result["last_name"] = instance.user.last_name
        result['is_active'] = instance.is_approved
        result["email"] = instance.user.email
        return result

    class Meta:
        model = Client
        fields = "__all__"

class InsuranceSerializer(serializers.ModelSerializer):

    class Meta:
        model = Insurance
        fields = "__all__"


class EhrSerializer(serializers.ModelSerializer):

    class Meta:
        model = Ehr
        fields = "__all__"


class HospitalDepartmentDropDownSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        result = {
            'id': instance.id,
            'name': instance.name,
            # 'hospital': instance.hospital.id if instance.hospital else None,
        }

        # if instance.hospital:
        #     result ['health_system'] = instance.hospital.health_system.id if instance.hospital.health_system else None
        # else:
        #     result ['health_system'] = None

        if instance.department_specialty.values('hospital'):
            for id_ in instance.department_specialty.values('hospital'):
                result['hospital'] = id_['hospital']

        else:
            result['hospital'] = None

        if instance.department_specialty.values('hospital__health_system__id'):
            for id_ in instance.department_specialty.values('hospital__health_system__id'):
                result['health_system'] = id_['hospital__health_system__id']

        else:
            result ['health_system'] = None

        return result

    class Meta:
        model = Department


class HealthSystemValidationSerializer(serializers.ModelSerializer):

    class Meta:
        model = HealthSystem
        fields = ('id', 'name', 'prefix')


class HospitalValidationSerializer(serializers.ModelSerializer):

    class Meta:
        model = Hospital
        fields = ('id', 'name')


class DepartmentValidationSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        result = {}
        result['id'] = instance.id
        result['name'] = instance.specialty.name
        return result


    class Meta:
        model = Department


class MemberListSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        result = {}
        result['id'] = instance.id
        result['first_name'] = instance.first_name
        result['last_name'] = instance.last_name
        result['email'] = instance.email
        result['role'] = instance.role
        result['name'] = f"{instance.first_name} {instance.last_name}"
        result['specialty'] = instance.specialties.values_list('name', flat=True).filter(id__in=self.context['specialties_ids'])
        return result