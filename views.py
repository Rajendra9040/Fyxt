from django.shortcuts import render
from django.db import transaction
from django.db.models import Avg, Min, Q, F, Max
from django.db.models.functions import ExtractWeek

import calendar
from datetime import datetime, timedelta
from openpyxl import load_workbook


from rest_framework.mixins import ListModelMixin
from rest_framework import status, permissions, viewsets
from rest_framework.response import Response
from rest_framework.decorators import action

from codequick.utils.mixins import SerializerClassMixin
from cqusers.utils import create_notification

from .models import AuditSheet, AuditHoursMonitor, AuditSheetComment, Industry, AuditSheetMetric
from .serializers import (
    AuditSheetSerializer, AuditHoursMonitorSerializer, IndustrySerializer,
    AuditSheetMetricSerializer, AuditorDropdownSerializer, AuditSheetHealthSystemSerializer,
    AuditSheetHospitalSerializer, AuditSheetDepartmentSerializer, AuditSheetCommentSerializer,
    RecentAuditsSerializer, ListUsersSerializer
)
from .utils import calculate_audit_metrics, provider_cq_score
from cqdashboard.models import Chart, ChartHistory
from cqusers.models import CqTeam, CqUser
from cqusers.pagination import CustomPagination, RecentAuditsPagination
from cqclient.utils import get_health_system_clients, get_hospital_clients, get_department_clients, get_providers_clients, calculate_cqgrade
from cqclient.models import HealthSystem, Hospital, Department, ProviderStatistics, Client
# Create your views here.


# Function to update audit sheet:
def update_audit_sheet(request, queryset, pk, flag=None):
    with transaction.atomic():
        chart_instance = Chart.objects.get(id=pk)

        existing_ids = [instance.id for instance in queryset.filter(chart_id=pk).order_by('index','row_id')]
        create_objects, update_objects, current_ids  = [], [], []
        for each_ in request.data:
            index = each_['index']
            sheet_name = each_['sheet_name']
            data = each_['data']
            for row_id, row in enumerate(data):
                row['row_id'] = row_id+1
                row['index'] = index
                row['sheet_name'] = sheet_name
                row['chart_id'] = pk

                if flag == 'update':
                    if (row.get('encounter_no') is None) or (row.get('rendering') is None) or (row.get('srvcs_no') is None) or (row.get('provider_rvu') is None) or (row.get('provider_dollar_value') is None) or (row.get('audited_code') is None) or (row.get('audited_rvu') is None) or (row.get('audited_dollar_value') is None):
                        error = {'errors':"The fields encounter_no, rendering, srvcs_no, provider_rvu, provider_dollar_value, audited_code, audited_rvu, audited_dollar_value can't be empty"}
                        return error

                if (flag=='create' and len(existing_ids)==0)  or row['id'] == None:
                    obj = AuditSheet(
                        chart_id = chart_instance,
                        row_id = row.get('row_id'),
                        index = row.get('index'),
                        sheet_name = row.get('sheet_name'),
                        encounter_no = row.get('encounter_no'),
                        rendering = Client.objects.get(id=row.get('rendering')) if row.get('rendering') else None,
                        srvcs_no = row.get('srvcs_no'),
                        enc_dt = row.get('enc_dt'),
                        provider_rvu = row.get('provider_rvu'),
                        provider_dollar_value = row.get('provider_dollar_value'),
                        response = row.get('response'),
                        agree = row.get('agree'),
                        disagree = row.get('disagree'),
                        audited_code = row.get('audited_code'),
                        audited_dollar_value = row.get('audited_dollar_value'),
                        audited_rvu = row.get('audited_rvu'),
                        notes = row.get('notes'),
                    )
                    create_objects.append(obj)

                else:
                    obj = AuditSheet.objects.get(id=row['id'])
                    obj.chart_id = chart_instance
                    obj.row_id = row.get('row_id')
                    obj.index = row.get('index')
                    obj.sheet_name = row.get('sheet_name')
                    obj.encounter_no = row.get('encounter_no')
                    obj.rendering = Client.objects.get(id=row.get('rendering')) if row.get("rendering") else None
                    obj.srvcs_no = row.get('srvcs_no')
                    obj.enc_dt = row.get('enc_dt')
                    obj.provider_rvu = row.get('provider_rvu')
                    obj.provider_dollar_value = row.get('provider_dollar_value')
                    obj.response = row.get('response')
                    obj.agree = row.get('agree') 
                    obj.disagree = row.get('disagree')
                    obj.audited_code = row.get('audited_code')
                    obj.audited_rvu = row.get('audited_rvu')
                    obj.audited_dollar_value = row.get('audited_dollar_value')
                    obj.notes = row.get('notes')
                    update_objects.append(obj)
                    current_ids.append(row['id'])

        delete_ids = [id for id in existing_ids if id  not in current_ids]
        AuditSheet.objects.filter(id__in=delete_ids).delete()

        if flag=='create' and len(existing_ids)!=0:
            AuditSheet.objects.bulk_create(create_objects)
            AuditSheet.objects.bulk_update(update_objects, fields=['row_id', 'index', 'sheet_name', 'encounter_no', 'rendering', 'srvcs_no', 'enc_dt', 'provider_rvu', 'provider_dollar_value','response', 'agree', 'disagree', 'audited_code', 'audited_rvu', 'audited_dollar_value', 'notes'])

        elif flag=='create' and len(existing_ids)==0:
            AuditSheet.objects.bulk_create(create_objects)

        elif flag=='update':
            if len(delete_ids) != 0:
                AuditSheetComment.objects.create(chart=chart_instance, audit_sheet_rows=delete_ids, audit_sheet_columns=[], user=request.user, action='DELETE')
            new_rows = AuditSheet.objects.bulk_create(create_objects)

            if len(new_rows) != 0:
                AuditSheetComment.objects.create(chart=chart_instance, audit_sheet_rows=[row.id for row in new_rows], audit_sheet_columns=[], user=request.user, action='ADD')
            AuditSheet.objects.bulk_update(update_objects, fields=['row_id', 'index', 'sheet_name', 'encounter_no', 'rendering', 'srvcs_no', 'enc_dt', 'provider_rvu', 'provider_dollar_value','response', 'agree', 'disagree', 'audited_code', 'audited_rvu', 'audited_dollar_value', 'notes'])

        audithour_instance = AuditHoursMonitor.objects.filter(chart_id=pk, user=request.user).order_by('-audit_start_time').first() 
        time = datetime.now() 
        if audithour_instance:                   
            audithour_instance.audit_end_time = time
            audithour_instance.save()           
        chart_instance.chart_updated_date = time
        chart_instance.save()


# Function to calculate average audit hours:
def avg_hours(members, range):
    avg = AuditHoursMonitor.objects.filter(user__in=members, audit_end_time__date__range= range).annotate(duration=F('audit_end_time') - F('audit_start_time')).exclude(duration='00:00:00').aggregate(Avg('duration'))['duration__avg']
    if avg:
        return round((avg/timedelta(hours=1)), 2)
    return 0


# Function to calculate average cq_score:
def avg_cq_score(users, range):
    avg_cq_score = AuditSheetMetric.objects.filter(provider__user__id__in=users, chart_id__upload_date__range=range).aggregate(Avg('cq_score'))['cq_score__avg']
    if avg_cq_score:
        return round(avg_cq_score)
    return 0


#Function to calculate average provider_avg_cq_score:
def provider_avg_cq_score(users, range):
    charts = Chart.objects.filter(Q(client=users) & ~Q(batch_id=None) & ~Q(is_deleted=False)).filter(archived_date__range=range)
    avg_cq_score = AuditSheetMetric.objects.filter(chart_id__in = charts).aggregate(Avg('cq_score'))['cq_score__avg']
    if avg_cq_score:
        return round(avg_cq_score)
    return 0 


class AuditSheetViewSet(SerializerClassMixin, viewsets.ModelViewSet):
    queryset = AuditSheet.objects.all()
    serializer_class = AuditSheetSerializer
    permission_classes = (permissions.IsAuthenticated,)

    @action(detail=True, methods=['post'], permission_classes=[permissions.AllowAny,])
    def post(self, request, pk):
        queryset=self.get_queryset()
        chart_instance = Chart.objects.get(id=pk)
        if request.user in [chart_instance.auditor, chart_instance.qa] or request.user.role == 'MANAGER':
            with transaction.atomic():
                update_audit_sheet(request, queryset, pk, flag='create')
                if chart_instance.auditor == request.user:
                    chart_instance.status = "IN PROGRESS"

                elif chart_instance.qa == request.user  and chart_instance.status != "QA REBUTTAL":
                    chart_instance.status = 'IN REVIEW'
                    ChartHistory.objects.create(user=request.user, chart=chart_instance, user_type='QA')
                chart_instance.save()
                return Response({"message":"Auditsheet created successfully"}, status=status.HTTP_201_CREATED)
        else:
            return Response({"message":"You do not have permission to edit/save this audit sheet data!"}, status=status.HTTP_403_FORBIDDEN)

    def update(self, request, pk):
        queryset=self.get_queryset()
        chart_instance = Chart.objects.get(id=pk)
        if request.user in [chart_instance.auditor, chart_instance.qa] or request.user.role == 'MANAGER':
            with transaction.atomic():
                error = update_audit_sheet(request, queryset, pk, flag='update')
                if error:
                    return Response(error, status=status.HTTP_400_BAD_REQUEST)
                if request.user.role in ['MANAGER', 'AUDITOR']:
                    chart_instance.status = 'AWAITING REVIEW'
                    chart_instance.audited_date=datetime.now()
                    all_active_qas = CqUser.objects.filter(role='QA', is_deleted=False, is_active=True)
                    create_notification("@ submitted an audit for QA", request.user, all_active_qas, 'TO REVIEW',chart_instance)
                    
                elif request.user.role in ['QA']:
                    chart_instance.status = 'ARCHIVED'
                    chart_instance.urgent_flag=False

                    calculate_audit_metrics(pk)
                    cq_score = provider_cq_score(chart_instance.client)
                    ProviderStatistics.objects.filter(provider=chart_instance.client).update(cq_score=cq_score)

                    all_active_managers = CqUser.objects.filter(role='MANAGER', is_deleted=False, is_active=True)
                    create_notification(f"@ submitted an audit for review to {chart_instance.client.user.first_name} {chart_instance.client.user.last_name}", request.user, all_active_managers, 'ARCHIVED', chart_instance)
                    if set(Chart.objects.filter(batch_id = chart_instance.batch_id).values_list('status', flat=True)) == {'ARCHIVED'}:
                        create_notification(f"{chart_instance.batch_id} has been submitted", request.user, [chart_instance.client.user], 'BATCH ARCHIVED', chart_instance)
                chart_instance.save()
                return Response({"message":"Auditsheet updated successfully"}, status=status.HTTP_201_CREATED)
        else:
            return Response({"message":"You do not have permission to edit/save this audit sheet data!"}, status=status.HTTP_403_FORBIDDEN)

    def retrieve(self, request, pk):
        queryset=self.get_queryset().filter(chart_id=pk).order_by('index','row_id') 
        indices = []
        for instance in queryset:
            if instance.index not in indices:
                indices.append(instance.index)
        response = []
        for index in indices:
            queryset_data = queryset.filter(index=index)
            serializer = self.get_serializer(queryset_data, many=True)
            response.append({
                "index":index,
                "sheet_name":queryset_data.first().sheet_name,
                "data":serializer.data
                })  
        return Response(response, status=status.HTTP_200_OK)


class AuditHoursMonitorViewset(SerializerClassMixin, viewsets.ModelViewSet):
    queryset = AuditHoursMonitor.objects.all()
    serializer_class = AuditHoursMonitorSerializer
    serializer_action_classes = {
        'recent_audits': RecentAuditsSerializer
    }
    permission_classes = (permissions.IsAuthenticated,)
    pagination_class = RecentAuditsPagination

    @action(detail=True, methods=['post'])
    def post(self, request, pk=None):
        chart = Chart.objects.get(id=pk)
        if chart.status == 'AWAITING REVIEW':
            chart.qa = request.user
            chart.status = 'IN REVIEW'
            ChartHistory.objects.create(user=request.user, chart=chart, user_type='QA')
        elif chart.status == 'AWAITING AUDIT':
            chart.status = 'IN PROGRESS'
        # if (request.user.role in ['AUDITOR','MANAGER'] and Chart.objects.get(id=pk).status in ['AWAITING AUDIT','IN PROGRESS']) or (request.user.role == 'QA' and Chart.objects.get(id=pk).status in ['AWAITING REVIEW','IN REVIEW']):
        time = datetime.now()
        AuditHoursMonitor.objects.create(chart_id=Chart.objects.get(id=pk), user=request.user, audit_start_time=time, audit_end_time=time)
        chart.save()
        return Response(status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        image = request.FILES.get('image', None)
        chart = Chart.objects.get(id=kwargs['pk'])


        instance = AuditHoursMonitor.objects.filter(chart_id=chart).last()
        instance.user = request.user
        instance.recent_audit_snaps = image
        instance.save()

        serializer = self.serializer_class(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path= "average")
    def avgaudithours(self, request, pk=None):
        start_date = self.request.query_params.get('start_date', None)
        end_date = self.request.query_params.get('end_date', None)
        previous_start_date = self.request.query_params.get('previous_start_date', None)
        previous_end_date = self.request.query_params.get('previous_end_date', None)
        if (start_date and end_date) and (not previous_start_date and not previous_end_date):
            return Response({
                'message':'Previous start date and end date need to provide',
                'error_code': 4081
            },status= status.HTTP_400_BAD_REQUEST)

        result = {
             "current_avg": 0,
	         "previous_diff": 0,
             "average_hours":{}
            }

        if user:=request.query_params.get('user'):
            members = CqUser.objects.filter(id=user)

        elif team:=request.query_params.get('team'):
            members = CqTeam.objects.get(id=team).members.all()

        if health_system_id:=request.query_params.get('health_system_id'):
            members = get_health_system_clients(health_system_id)
            if not members:
                return Response({"message": "No HealthSystem matches the given query."}, status=status.HTTP_400_BAD_REQUEST)

        if hospital_id:=request.query_params.get('hospital_id'):
            members = get_hospital_clients(hospital_id)
            if not members:
                return Response({"message": "No Hospital matches the given query."}, status=status.HTTP_400_BAD_REQUEST)

        if department_id:=request.query_params.get('department_id'):
            members = get_department_clients(department_id)
            if not members:
                return Response({"message": "No Department matches the given query."}, status=status.HTTP_400_BAD_REQUEST)

        if provider_id:=request.query_params.get('provider_id'):
            members = get_providers_clients(provider_id)
            if not members:
                return Response({"message": "No Providers matches the given query."}, status=status.HTTP_400_BAD_REQUEST)

        if (not start_date) and (not end_date):
            end_date = datetime.today() - timedelta(days=1)
            start_date = end_date - timedelta(days=7)
            previous_end_date = start_date - timedelta(days=1)
            previous_start_date = previous_end_date - timedelta(days=7)
            current_avg = avg_hours(members, [start_date, end_date])
            previous_avg = avg_hours(members, [previous_start_date, previous_end_date])
        
        time_range = [start_date, end_date]
        current_avg = avg_hours(members, time_range)
        previous_avg = avg_hours(members, [previous_end_date, previous_start_date])
        result['current_avg'] = current_avg
        result['previous_diff'] = current_avg - previous_avg

        for day in range(7, 0, -1): 
            average_hours = AuditHoursMonitor.objects.filter(user__in=members, audit_end_time=datetime.today() - timedelta(days=day)).annotate(duration=F('audit_end_time') - F('audit_start_time')).exclude(duration='00:00:00').aggregate(Avg('duration'))['duration__avg']
            if average_hours:
                average_hours /= timedelta(hours=1)
            else:
                average_hours = 0
            result['average_hours'][(datetime.today() - timedelta(days=day)).weekday()] = round(average_hours, 2)  

        return Response(result, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path= "recent_audits")
    def recent_audits(self, request):
        user = request.user
        if user.role in ("AUDITOR", "MANAGER"):
            queryset = self.get_queryset().filter(user=request.user, chart_id__auditor=request.user, chart_id__status="IN PROGRESS", chart_id__is_deleted=False).values('user', 'chart_id').annotate(latest = Max('audit_end_time')).order_by('-latest')

        if user.role == "QA":
            queryset = self.get_queryset().filter(user=request.user, chart_id__qa=request.user, chart_id__status__in=["IN REVIEW", "ARCHIVED"], chart_id__is_deleted=False).values('user', 'chart_id').annotate(latest = Max('audit_end_time')).order_by('-latest')

        # page = self.paginate_queryset(queryset)
        # if page is not None:
        #     serializer = self.get_serializer_class()(page, many=True)
        #     return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data[:5], status=status.HTTP_200_OK)


class IndustryViewSet(viewsets.ModelViewSet):
    queryset = Industry.objects.all()
    serializer_class = IndustrySerializer
    permission_classes = (permissions.IsAuthenticated,) 

    def create(self, request, *args, **kwargs):
        industry_file = request.FILES['industry_file'] 
        book = load_workbook(industry_file)
        sheet1 = book['Washington, Area 02']
        column_list =[sheet1.cell(row =9, column=column_).value for column_ in range(1,sheet1.max_column+1)]
        for row_ in range(10,sheet1.max_row+1):
            if sheet1.cell(row =row_, column=1).value is None:
                type = "CPT"
                code = sheet1.cell(row =row_, column=column_list.index('Procedure Code')+1).value
                modifier = sheet1.cell(row =row_, column=(column_list.index('Modifier'))+1).value
                par_amount = sheet1.cell(row =row_, column=(column_list.index('Par Amount'))+1).value
                non_par_amount = sheet1.cell(row =row_, column=(column_list.index('Non-Par Amount'))+1).value
                limiting_charge_amount = sheet1.cell(row =row_, column=(column_list.index('Limiting Charge Amount'))+1).value
                try:
                    if int(code) >= 99202:
                        type= "E&M"
                except:
                    pass

                Industry.objects.create(
                    code=code,
                    type =type,
                    modifier=modifier,
                    par_amount=par_amount,
                    non_par_amount=non_par_amount,
                    limiting_charge_amount=limiting_charge_amount
                    )

        return Response('data saved successfully',status=status.HTTP_201_CREATED)

    def list(self, request, *args, **kwargs):
        queryset =self.get_queryset().order_by('id')
        response={}
        for object in queryset:
            if object.modifier == None:
                response[object.code] = object.limiting_charge_amount
            elif object.modifier:
                response[f"{object.code}-{object.modifier}"] = object.limiting_charge_amount

        return Response(response, status=status.HTTP_200_OK)


class AuditSheetMetricViewSet(viewsets.ModelViewSet):
    queryset = AuditSheetMetric.objects.all()
    serializer_class = AuditSheetMetricSerializer
    permission_classes = (permissions.IsAuthenticated,)

    @action(detail=True, methods=['post'])
    def post(self, request, pk=None):
        chart_queryset = AuditSheet.objects.filter(chart_id=pk, disagree=True).annotate(rvu_diff = F("provider_rvu") - F("audited_rvu"))
        total_object_count = chart_queryset.count()
        if total_object_count == 0:
            return Response('No auditsheet related to given chart_id found')
        upcoded = chart_queryset.filter(rvu_diff__gt =0).count()
        downcoded = chart_queryset.filter(rvu_diff__lt =0).count()
        rvu = upcoded + downcoded #chart_queryset.filter(~Q(rvu_diff=0)).count()
        modifier = chart_queryset.filter(~Q(srvcs_no__contains ='-'), Q(audited_code__contains ='-')).count()
        upcoded_percentage = round((1 - (upcoded/total_object_count))*100,2)
        downcoded_percentage = round((1 - (downcoded/total_object_count))*100,2)
        rvu_percentage = round((1 - (rvu/total_object_count))*100,2)
        modifier_percentage = round((1 - (modifier/total_object_count))*100,2)
        cq_score = round((upcoded_percentage + downcoded_percentage + rvu_percentage + modifier_percentage)/4,2) 

        AuditSheetMetric.objects.update_or_create(
            defaults = {
                "upcoded": upcoded,
                "upcoded_percentage": upcoded_percentage,
                "downcoded": downcoded,
                "downcoded_percentage": downcoded_percentage,
                "rvu": rvu,
                "rvu_percentage": rvu_percentage,
                "modifier": modifier,
                "modifier_percentage": modifier_percentage,
                "cq_score":cq_score,
            },
            chart_id = Chart.objects.get(id=pk),        
        )
        return Response('Audit metric calculated successfully', status=status.HTTP_201_CREATED)
    
    @action(detail=False, methods=['get'], url_path='chart-accuracy')
    def chart_accuracy(self, request, pk=None):
        start_date = self.request.query_params.get('start_date',None)
        end_date = self.request.query_params.get('end_date',None)
        previous_start_date = self.request.query_params.get('previous_start_date',None)
        previous_end_date = self.request.query_params.get('previous_end_date',None)

        if (start_date != None and end_date != None) and (previous_start_date == None or previous_end_date == None):
            return Response({
                'message':'Previous start date and end date need to provide',
                'error_code': 4081
            },status= status.HTTP_400_BAD_REQUEST)

        response = {
                "grade" :0, 
                "cq_score":0,
                "cq_score_diff":0, 
            }

        if user:=request.query_params.get('user'):
            members = CqUser.objects.filter(id=user)

        elif team:=request.query_params.get('team'):
            members = CqTeam.objects.get(id=team).members.all()

        if health_system_id:=request.query_params.get('health_system_id'):
            members = get_health_system_clients(health_system_id)
            if not members:
                return Response({"message": "No HealthSystem matches the given query."}, status=status.HTTP_400_BAD_REQUEST)

        if hospital_id:=request.query_params.get('hospital_id'):
            members = get_hospital_clients(hospital_id)
            if not members:
                return Response({"message": "No Hospital matches the given query."}, status=status.HTTP_400_BAD_REQUEST)

        if department_id:=request.query_params.get('department_id'):
            members = get_department_clients(department_id)
            if not members:
                return Response({"message": "No Department matches the given query."}, status=status.HTTP_400_BAD_REQUEST)

        if provider_id:=request.query_params.get('provider_id'):
            members = get_providers_clients(provider_id)
            if not members:
                return Response({"message": "No Providers matches the given query."}, status=status.HTTP_400_BAD_REQUEST)


        if (start_date is None) and (end_date is None):
            end_date = datetime.today() - timedelta(days=1)
            start_date = end_date - timedelta(days=30)
            previous_end_date = start_date - timedelta(days=1)
            previous_start_date = previous_end_date - timedelta(days=30)
        current_avg_cq_score = avg_cq_score(members, [start_date, end_date])
        previous_avg_cq_score = avg_cq_score(members, [previous_start_date, previous_end_date])


        response['cq_score'] = current_avg_cq_score
        response['cq_score_diff'] = round(current_avg_cq_score - previous_avg_cq_score, 3)
        response['grade'] = calculate_cqgrade(current_avg_cq_score)

        return Response(response, status=status.HTTP_200_OK)


def weekly_cq_accuracy(start_date, end_date, week):
    charts = Chart.objects.filter(archived_date__range=[start_date, end_date], is_deleted=False)
    week_wise_queryset = AuditSheetMetric.objects.filter(chart_id__in=charts).annotate(week_num=ExtractWeek('chart_id__archived_date'))
    week_cq_score_percentage = week_wise_queryset.filter(week_num=week + week_wise_queryset.aggregate(Min('week_num'))['week_num__min']).aggregate(Avg('cq_score'))['cq_score__avg']
    if week_cq_score_percentage:
        return week_cq_score_percentage
    else:
        return 0

def weekly_audited(start_date, end_date, week):
    charts = Chart.objects.filter(archived_date__range=[start_date, end_date], is_deleted=False)
    week_wise_queryset = AuditSheetMetric.objects.filter(chart_id__in=charts).annotate(week_num=ExtractWeek('chart_id__archived_date'))
    audited_queryset = Chart.objects.filter(status = 'ARCHIVED', is_deleted = False, audited_date__range=[start_date,end_date]).filter(~Q(batch_id=None))
    weekly_audited = audited_queryset.annotate(week_num=ExtractWeek('audited_date')).filter(week_num=week + week_wise_queryset.aggregate(Min('week_num'))['week_num__min']).count()
    return weekly_audited

def weekly_error(start_date, end_date, week):
    charts = Chart.objects.filter(archived_date__range=[start_date, end_date], is_deleted=False)
    week_wise_queryset = AuditSheetMetric.objects.filter(chart_id__in=charts).annotate(week_num=ExtractWeek('chart_id__archived_date'))
    auditsheet_queryset = AuditSheet.objects.filter(chart_id__status = 'ARCHIVED', chart_id__is_deleted = False, chart_id__audited_date__range=[start_date,end_date]).filter(~Q(chart_id__batch_id=None)).filter(disagree=True)
    weekly_error = auditsheet_queryset.annotate(week_num=ExtractWeek('chart_id__audited_date')).filter(week_num=week + week_wise_queryset.aggregate(Min('week_num'))['week_num__min']).count()
    return weekly_error

def cq_accuracy(start_date, end_date):
    charts = Chart.objects.filter(archived_date__range=[start_date,end_date], is_deleted=False)
    cq_accuracy = AuditSheetMetric.objects.filter(chart_id__in =charts).aggregate(Avg('cq_score'))['cq_score__avg']
    if cq_accuracy:
        return cq_accuracy
    return 0

def audited(start_date, end_date):
    audited_queryset = Chart.objects.filter(status = 'ARCHIVED', is_deleted = False, audited_date__range=[start_date, end_date]).filter(~Q(batch_id=None))
    return audited_queryset.count()

def error(start_date, end_date):
    auditsheet_queryset = AuditSheet.objects.filter(chart_id__status = 'ARCHIVED', chart_id__is_deleted = False, chart_id__audited_date__range=[start_date,end_date]).filter(~Q(chart_id__batch_id=None)).filter(disagree=True)
    error = auditsheet_queryset.count()
    return error


class ReportViewSet(viewsets.ModelViewSet):
    queryset = AuditSheetMetric.objects.all()
    serializer_class = AuditSheetMetricSerializer
    permission_classes = (permissions.IsAuthenticated, )

    @action(detail=True, methods=['get'],url_path='weekdays-accuracy')
    def weekdays_accuracy(self, request, pk=None):
        end_date = datetime.today().replace(day=1, hour=23) - timedelta(days=1)
        start_date = datetime.today().replace(month =datetime.today().month-1,day=1,hour=0)
        response = {}
        if calendar.monthrange(datetime.today().year, 2)[1] == 28 and datetime.today().month == 2:
            week = 4
        else:
            week = 5

        charts = Chart.objects.filter(archived_date__range=[start_date, end_date], is_deleted=False)

        if health_system_id:=request.query_params.get('health_system_id'):
            client_user_ids = get_health_system_clients(health_system_id)

            if not client_user_ids:
                return Response({"message": "No HealthSystem matches the given query."}, status=status.HTTP_400_BAD_REQUEST)
            charts = Chart.objects.filter(client__user_id__in=client_user_ids, archived_date__range=[start_date, end_date], is_deleted=False)


        if hospital_id:=request.query_params.get('hospital_id'):
            client_user_ids = get_hospital_clients(hospital_id)

            if not client_user_ids:
                return Response({"message": "No Hospital matches the given query."}, status=status.HTTP_400_BAD_REQUEST)
            charts = Chart.objects.filter(client__user_id__in=client_user_ids, archived_date__range=[start_date, end_date], is_deleted=False)


        if specialty_id:=request.query_params.get('specialty_id'):
            client_user_ids = get_department_clients(specialty_id)

            if not client_user_ids:
                return Response({"message": "No Specialty matches the given query."}, status=status.HTTP_400_BAD_REQUEST)
            charts = Chart.objects.filter(client__user_id__in=client_user_ids, archived_date__range=[start_date, end_date], is_deleted=False)


        if providers_id:=request.query_params.get('providers_id'):
            client_user_ids = get_providers_clients(providers_id)

            if not client_user_ids:
                return Response({"message": "No Providers matches the given query."}, status=status.HTTP_400_BAD_REQUEST)
            charts = Chart.objects.filter(client__user_id__in=client_user_ids, archived_date__range=[start_date, end_date], is_deleted=False)

        # else:
        #     charts = Chart.objects.filter(archived_date__range=[start_date, end_date])

        for week in range(week):
            audit_sheet_metric_queryset = AuditSheetMetric.objects.filter(chart_id__in=charts)
            if audit_sheet_metric_queryset:
                week_wise_queryset = audit_sheet_metric_queryset.annotate(week_num=ExtractWeek('chart_id__archived_date'))
                week_cq_score_percentage = week_wise_queryset.filter(week_num=week + week_wise_queryset.aggregate(Min('week_num'))['week_num__min']).aggregate(Avg('cq_score'))['cq_score__avg']
                week_cq_score = week_cq_score_percentage if week_cq_score_percentage else 0
            else:
                week_cq_score = 0

            response[f'week{week+1}'] = {}
            response[f'week{week+1}']['cq_accuracy'] = week_cq_score 
            response[f'week{week+1}']['error'] = 100 - week_cq_score if week_cq_score !=0 else 0

        # for week in range(week):
        #     response[f'week{week+1}'] = {}
        #     response[f'week{week+1}']['cq_accuracy'] = weekly_cq_accuracy(start_date, end_date, week) 
        #     response[f'week{week+1}']['error'] = 100 - weekly_cq_accuracy(start_date, end_date, week)  
        return Response(response, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='error-parameter-dropdown')
    def error_parameter_dropdown(self, request):
        response = [
            {
                'label':'CPT',
                'value':'CPT'
            },
            {
                'label':'E&M',
                'value':'E&M'
            },
            {
                'label':'ICD',
                'value':'ICD'
            },
            {
                'label':'Client Specification',
                'value':'Client_Specification'
            },
            {
                'label':'Provider',
                'value':'Provider'
            },
            {
                'label':'Modifier',
                'value':'Modifier'  
            },
            {
                'label':'Procedure',
                'value':'Procedure'  
            },
            {
                'label':'Vaccine',
                'value':'Vaccine'
            },
            {
                'label':'MIPS',
                'value':'MIPS'
            }
        ]

        return Response(response)

    @action(detail=True, methods=['get'], url_path='week-wise-error')
    def weekdays_error(self, request, pk=None):
        parameters = [parameter for parameter in self.request.query_params.get('parameters','CPT,E&M').split(',')]
        end_date = datetime.today().replace(day=1, hour=23) - timedelta(days=1)
        start_date = datetime.today().replace(month =datetime.today().month-1,day=1,hour=0)
        response = {}

        charts = Chart.objects.filter(status='ARCHIVED', is_deleted=False, archived_date__range=[start_date, end_date])
        # queryset = AuditSheet.objects.filter(chart_id__status='ARCHIVED', chart_id__archived_date__range=[start_date, end_date], disagree=True).annotate(week_num=ExtractWeek('chart_id__archived_date'))

        if health_system_id:=request.query_params.get('health_system_id'):
            client_user_ids = get_health_system_clients(health_system_id)

            if not client_user_ids:
                return Response({"message": "No HealthSystem matches the given query."}, status=status.HTTP_400_BAD_REQUEST)
            charts = charts.filter(client__user_id__in=client_user_ids)


        if hospital_id:=request.query_params.get('hospital_id'):
            client_user_ids = get_hospital_clients(hospital_id)

            if not client_user_ids:
                return Response({"message": "No Hospital matches the given query."}, status=status.HTTP_400_BAD_REQUEST)
            charts = charts.filter(client__user_id__in=client_user_ids)


        if specialty_id:=request.query_params.get('specialty_id'):
            client_user_ids = get_department_clients(specialty_id)

            if not client_user_ids:
                return Response({"message": "No Specialty matches the given query."}, status=status.HTTP_400_BAD_REQUEST)
            charts = charts.filter(client__user_id__in=client_user_ids)


        if providers_id:=request.query_params.get('providers_id'):
            client_user_ids = get_providers_clients(providers_id)

            if not client_user_ids:
                return Response({"message": "No Providers matches the given query."}, status=status.HTTP_400_BAD_REQUEST)
            charts = charts.filter(client__user_id__in=client_user_ids)

        queryset = AuditSheet.objects.filter(chart_id__in=charts, disagree=True).annotate(week_num=ExtractWeek('chart_id__archived_date'))
        code = []
        for each_ in queryset:
            code.append(each_.audited_code) if ('-' not in each_.audited_code) else code.append(each_.audited_code.split('-')[0])
        response['current_month'] = {}
        response['current_month']['CPT']= Industry.objects.filter(code__in=code, type='CPT').count() 
        response['current_month']['E&M']= Industry.objects.filter(code__in=code, type='E&M').count()

        if calendar.monthrange(datetime.today().year, 2)[1] == 28 and datetime.today().month == 2 :
            total_week = 4
        else:
            total_week = 5

        year = datetime.today().year
        month = datetime.today().month
        first_week = datetime(year, month, calendar.monthrange(year, month)[0]).isocalendar()[1]
        for week in range(total_week):
            weekly_queryset = queryset.filter(week_num = week + first_week)
            code =[]
            for each_ in weekly_queryset:
                code.append(each_.audited_code) if ('-' not in each_.audited_code) else code.append(each_.audited_code.split('-')[0])
            response[f'week{week+1}'] = {}
            response[f'week{week+1}']['CPT']= Industry.objects.filter(code__in=code,type = 'CPT').count() 
            response[f'week{week+1}']['E&M']= Industry.objects.filter(code__in=code,type = 'E&M').count()

        if self.request.query_params.get('graph') == 'True':
            return Response(response, status=status.HTTP_200_OK)

        else:
            """ result and response are for two different query_param """
            result = []
            for parameter in parameters:
                row ={}
                if parameter == 'CPT' or parameter == 'E&M':
                    row['error_parameter'] = parameter
                    row['current_month'] = response['current_month'][parameter]
                    for week in range(total_week):
                        weekly_queryset = queryset.filter(week_num = week + first_week)
                        code =[]
                        for each_ in weekly_queryset:
                            code.append(each_.audited_code) if ('-' not in each_.audited_code) else code.append(each_.audited_code.split('-')[0])
                        row[f'week{week+1}']= Industry.objects.filter(code__in=code, type=parameter).count() 
                else:
                    row['error_parameter'] = parameter
                    row['current_month'] = 0
                    for week in range(total_week):
                        row[f'week{week+1}'] = 0
                result.append(row)
            total_current_month = 0
            total_week1 = 0
            total_week2 = 0
            total_week3 = 0
            total_week4 = 0
            total_week5 = 0 
            [total_current_month := total_current_month + i['current_month'] for i in result]
            [total_week1 := total_week1 + i['week1'] for i in result]
            [total_week2 := total_week2 + i['week2'] for i in result]
            [total_week3 := total_week3 + i['week3'] for i in result]
            [total_week4 := total_week4 + i['week4'] for i in result]
            [total_week5 := total_week1 + i['week5'] for i in result if total_week == 5 ]        
            total ={
                'error_parameter': 'Total',
                'current_month': total_current_month,
                'week1': total_week1,
                'week2': total_week2,
                'week3': total_week3,
                'week4': total_week4,
            }
            if total_week == 5:     
                total['week5'] = total_week5
            result.append(total)
        return Response(result, status=status.HTTP_200_OK) 

    @action(detail=False, methods=['get'], url_path='cq-accuracy-error')
    def cq_accuracy_error(self, request, pk=None):
        end_date = datetime.today().replace(day=1, hour=23) - timedelta(days=1)
        start_date = datetime.today().replace(month =datetime.today().month-1, day=1, hour=0)

        monthly_data =[audited(start_date, end_date), error(start_date, end_date), cq_accuracy(start_date,end_date), 100 - cq_accuracy(start_date,end_date) if cq_accuracy(start_date,end_date) !=0 else 0]
        heading = ['audited', 'error', 'cq_score_percentage', 'error_percentage']
        response = []
        charts = Chart.objects.filter(is_deleted=False, archived_date__range=[start_date, end_date])


        if health_system_id:=request.query_params.get('health_system_id'):
            client_user_ids = get_health_system_clients(health_system_id)

            if not client_user_ids:
                return Response({"message": "No HealthSystem matches the given query."}, status=status.HTTP_400_BAD_REQUEST)
            charts = charts.filter(client__user_id__in=client_user_ids)


        if hospital_id:=request.query_params.get('hospital_id'):
            client_user_ids = get_hospital_clients(hospital_id)

            if not client_user_ids:
                return Response({"message": "No Hospital matches the given query."}, status=status.HTTP_400_BAD_REQUEST)
            charts = charts.filter(client__user_id__in=client_user_ids)


        if specialty_id:=request.query_params.get('specialty_id'):
            client_user_ids = get_department_clients(specialty_id)

            if not client_user_ids:
                return Response({"message": "No Specialty matches the given query."}, status=status.HTTP_400_BAD_REQUEST)
            charts = charts.filter(client__user_id__in=client_user_ids)


        if providers_id:=request.query_params.get('providers_id'):
            client_user_ids = get_providers_clients(providers_id)

            if not client_user_ids:
                return Response({"message": "No Providers matches the given query."}, status=status.HTTP_400_BAD_REQUEST)
            charts = charts.filter(client__user_id__in=client_user_ids)


        # else:
        #     charts = Chart.objects.filter(archived_date__range=[start_date, end_date])

        week_wise_queryset = AuditSheetMetric.objects.filter(chart_id__in=charts).annotate(week_num=ExtractWeek('chart_id__archived_date'))

        for data_ in range(4):
            response.append({}) 
            response[data_]['specifics'] = heading[data_]
            response[data_]['current_month'] = monthly_data[data_]
            if calendar.monthrange(datetime.today().year, 2)[1] == 28 and datetime.today().month == 2 :
                week = 4
            else:
                week = 5

            for week in range(week):

                # To get Weekly Cq_Score:
                if week_wise_queryset:
                    week_cq_score_percentage = week_wise_queryset.filter(week_num=week+week_wise_queryset.aggregate(Min('week_num'))['week_num__min']).aggregate(Avg('cq_score'))['cq_score__avg']
                    week_cq_score = week_cq_score_percentage if week_cq_score_percentage else 0
                else:
                    week_cq_score = 0

                # To get weekly audited:
                audited_queryset = Chart.objects.filter(status='ARCHIVED', is_deleted=False, audited_date__range=[start_date, end_date]).filter(~Q(batch_id=None))
                if audited_queryset:
                    weekly_audited_score = audited_queryset.annotate(week_num=ExtractWeek('audited_date')).filter(week_num=week+week_wise_queryset.aggregate(Min('week_num'))['week_num__min']).count()        
                else:
                    weekly_audited_score = 0

                #To get weekly error:
                auditsheet_queryset = AuditSheet.objects.filter(chart_id__status='ARCHIVED', chart_id__is_deleted=False, chart_id__audited_date__range=[start_date, end_date]).filter(~Q(chart_id__batch_id=None)).filter(disagree=True)
                if auditsheet_queryset:
                    weekly_error_score = auditsheet_queryset.annotate(week_num=ExtractWeek('chart_id__audited_date')).filter(week_num=week+week_wise_queryset.aggregate(Min('week_num'))['week_num__min']).count()
                else:
                    weekly_error_score = 0

                weekly_data = [
                    weekly_audited_score,
                    weekly_error_score,
                    week_cq_score,
                    100 - week_cq_score if week_cq_score !=0 else 0,

                    # weekly_audited(start_date, end_date, week),
                    # weekly_error(start_date, end_date, week),
                    # weekly_cq_accuracy(start_date, end_date, week),
                    # 100 - weekly_cq_accuracy(start_date, end_date, week)
                ]
                response[data_][f'week{week+1}'] = weekly_data[data_]
        return Response(response)
 
    @action(detail=False, methods=['get'], url_path='auditor-quality')
    def auditor_quality(self, request, pk=None):
        auditor_id = self.request.query_params.get('auditor')
        if auditor_id is None:
            auditor = CqUser.objects.filter(role='AUDITOR')
        else:
            auditor = CqUser.objects.filter(id=int(auditor_id))
        response = [{},{},{}]
        auditsheets = AuditSheet.objects.filter(chart_id__status="ARCHIVED", chart_id__auditor__in=auditor, chart_id__is_deleted=False)
        code =[]
        for each_ in auditsheets:
            if each_.srvcs_no is not None:
                if ('-' not in each_.srvcs_no):
                    code.append(each_.srvcs_no)
                else:
                    code.append(each_.srvcs_no.split('-')[0])
        audited_overall = auditsheets.filter(~Q(srvcs_no = None)).count()
        audited_e_and_m = Industry.objects.filter(code__in=code, type = 'E&M').count()
        audited_mod = auditsheets.filter(srvcs_no__contains ='-').count()
        response[0]['Quality'] = 'Audited'
        response[0]['overall'] = audited_overall
        response[0]['cpt'] = audited_overall - audited_e_and_m 
        response[0]['e&m'] = audited_e_and_m
        response[0]['mod'] = audited_mod

        error_auditsheets = AuditSheet.objects.filter(chart_id__status="ARCHIVED", disagree=True, chart_id__auditor__in=auditor)
        code =[]
        for each_ in error_auditsheets:
            if each_.audited_code is not None:
                if ('-' not in each_.audited_code):
                    code.append(each_.audited_code)
                else:
                    code.append(each_.audited_code.split('-')[0])
        error_overall = error_auditsheets.filter(~Q(srvcs_no = None)).count()
        error_e_and_m = Industry.objects.filter(code__in=code, type = 'E&M').count()
        error_mod = error_auditsheets.filter(srvcs_no__contains ='-').count()
        response[1]['Quality'] = 'Error'
        response[1]['overall'] = error_overall
        response[1]['cpt'] = error_overall - error_e_and_m 
        response[1]['e&m'] = error_e_and_m
        response[1]['mod'] = error_mod
        
        response[2]['Quality'] = 'Accuracy%'
        response[2]['overall'] = round((1 - error_overall/audited_overall)*100, 2) if (audited_overall != 0) else None
        response[2]['cpt'] = round((1 - (error_overall-error_e_and_m)/(audited_overall-audited_e_and_m))*100, 2) if ((audited_overall-audited_e_and_m) != 0) else None
        response[2]['e&m'] = round((1 - error_e_and_m/audited_e_and_m)*100, 2) if (audited_e_and_m != 0) else None
        response[2]['mod'] = round((1 - error_mod/audited_mod)*100, 2) if (audited_mod != 0) else None

        return Response(response, status=status.HTTP_200_OK) 

    @action(detail=False, methods=['get'], url_path='auditor-dropdown')
    def auditor_dropdown(self, request):
        auditor = CqUser.objects.filter(role__in=['AUDITOR', 'MANAGER']).order_by('id', 'first_name').distinct('id')
        serializer = AuditorDropdownSerializer(auditor, many=True) 
        return Response(serializer.data, status=status.HTTP_200_OK) 
        

class AuditSheetCommentViewSet(viewsets.ModelViewSet):
    queryset = AuditSheetComment.objects.all()
    serializer_class = AuditSheetCommentSerializer
    permission_classes = (permissions.IsAuthenticated,) 
    pagination_class = CustomPagination

    def retrieve(self, request, pk):
        row = [int(row) for row in self.request.query_params.get('row').split(',')] if request.query_params.get('row') != None else None
        column = [column for column in self.request.query_params.get('column').split(',')] if request.query_params.get('column') != None else None 
        sheet_name = self.request.query_params.get('sheet_name')
        queryset = self.get_queryset().filter(chart=pk, parent=None).order_by('updated_at')

        if row != None and column != None:
            queryset = queryset.filter(audit_sheet_rows=row, audit_sheet_columns=column).order_by('updated_at')

        elif row != None and column == None:
            queryset = queryset.filter(audit_sheet_rows=row).order_by('updated_at')

        elif row == None and column != None:
            queryset = queryset.filter(audit_sheet_columns=column).order_by('updated_at')

        elif sheet_name != None:
            rows =[object.id for object in AuditSheet.objects.filter(chart_id=pk, sheet_name__iexact = sheet_name.strip()) ]
            if sheet_name.startswith("-"):
                queryset = queryset.filter(audit_sheet_rows__contained_by = rows).order_by('-updated_at')
            else:
                queryset =  queryset.filter(audit_sheet_rows__contained_by = rows).order_by('updated_at')

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer_class()(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        request.data['user'] = request.user.id
        request.data['chart'] = AuditSheet.objects.get(id=request.data['audit_sheet_rows'][0]).chart_id.id if request.data["audit_sheet_rows"] != [] else request.data['chart']
        chart = Chart.objects.get(id=request.data["chart"])
        if (request.data.get('action') == "REBUTTAL") and (chart.status not in ['QA REBUTTAL','CLIENT REBUTTAL']):
            if request.user.role == "CLIENT":
                chart.status = "CLIENT REBUTTAL"
                create_notification(f"@ submitted a rebuttal", request.user, CqUser.objects.filter(role__in=['QA', 'MANAGER'], is_active=True, is_deleted=False), 'CLIENT REBUTTAL', chart)
            else:
                chart.status = 'QA REBUTTAL'
                create_notification(f"@ submitted a rebuttal to {chart.auditor.first_name} {chart.auditor.last_name}", request.user, [chart.auditor], 'QA REBUTTAL', chart)
            chart.urgent_flag = True
            chart.save()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        receiver = CqUser.objects.filter(id__in=request.data["tagged_user"])
        chart = Chart.objects.get(id=request.data["chart"])
        create_notification(f"@ tagged you in a comment", request.user, receiver, 'COMMENT', chart)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response({"message":"Requested comment deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
    
    @action(detail=True, methods=['get'], url_path='cell_flag')
    def cell_flag(self, request, pk):
        queryset = self.get_queryset().filter(chart=pk).order_by('updated_at')
        if sheet_name:=self.request.query_params.get("sheet_name"):
            rows =[object.id for object in AuditSheet.objects.filter(chart_id=pk, sheet_name__iexact = sheet_name.strip())]
            queryset =  queryset.filter(audit_sheet_rows__contained_by = rows).order_by('updated_at')
        response = [(instance.audit_sheet_rows, instance.audit_sheet_columns) for instance in queryset if instance.audit_sheet_rows or instance.audit_sheet_columns]
        return Response(response)
    
    @action(detail=True, methods=['get'], url_path='client_comment')
    def client_comment(self, request, pk):
        charts = Chart.objects.filter(batch_id=pk)
        row = [int(row) for row in self.request.query_params.get('row').split(',')] if request.query_params.get('row') != None else None
        column = [column for column in self.request.query_params.get('column').split(',')] if request.query_params.get('column') != None else None 
        sheet_name = self.request.query_params.get('sheet_name')
        queryset = self.get_queryset().filter(chart__in=Chart.objects.filter(batch_id=pk)).filter(Q(tagged_user__contains=[request.user.id]) | Q(user=request.user)).order_by('updated_at')

        if row != None and column != None:
            queryset = queryset.filter(audit_sheet_rows=row, audit_sheet_columns=column).order_by('updated_at')

        elif row != None and column == None:
            queryset = queryset.filter(audit_sheet_rows=row).order_by('updated_at')

        elif row == None and column != None:
            queryset = queryset.filter(audit_sheet_columns=column).order_by('updated_at')

        elif sheet_name != None:
            rows =[object.id for object in AuditSheet.objects.filter(chart_id__in=charts, sheet_name__iexact = sheet_name.strip())]
            if sheet_name.startswith("-"):
                queryset = queryset.filter(audit_sheet_rows__contained_by = rows).order_by('-updated_at')
            else:
                queryset =  queryset.filter(audit_sheet_rows__contained_by = rows).order_by('updated_at')

        parent_comment_list = []
        for comment in queryset:
            if comment.parent==None:
                parent_comment_list.append(comment)
            else:
                parent_comment_list.append(comment.parent)

        page = self.paginate_queryset(parent_comment_list)
        if page is not None:
            serializer = self.get_serializer_class()(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(parent_comment_list, many=True) 
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @action(detail=True, methods=['get'], url_path='client_rebuttal_comment')
    def client_rebuttal_comment(self, request, pk):
        queryset = self.get_queryset().filter(chart__in=Chart.objects.filter(batch_id=pk), action__in=["REBUTTAL",]).filter(Q(tagged_user__contains=[request.user.id]) | Q(user=request.user)).distinct().order_by('updated_at')
        parent_comment_list = []
        for comment in queryset:
            if comment.parent==None and comment not in parent_comment_list:
                parent_comment_list.append(comment)
            elif comment.parent not in parent_comment_list:
                parent_comment_list.append(comment.parent)
        page = self.paginate_queryset(parent_comment_list)
        if page is not None:
            serializer = self.get_serializer_class()(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(parent_comment_list, many=True) 
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @action(detail=True, methods=['get'], url_path='client_cell_flag')
    def client_cell_flag(self, request, pk):
        queryset = self.get_queryset().filter(chart__in=Chart.objects.filter(batch_id=pk)).order_by('updated_at')
        print([i.id for i in queryset])
        if sheet_name:=self.request.query_params.get("sheet_name"):
            rows =[object.id for object in AuditSheet.objects.filter(chart_id__batch_id=pk, sheet_name__iexact = sheet_name.strip())]
            queryset =  queryset.filter(audit_sheet_rows__contained_by = rows).order_by('updated_at')    
        response = [(instance.audit_sheet_rows, instance.audit_sheet_columns) for instance in queryset if instance.audit_sheet_rows or instance.audit_sheet_columns]
        return Response(response)

    @action(detail=False, methods=['post'], url_path='updation_activity')
    def updation_activity(self, request):
        objects = []
        for data in request.data:
            chart = AuditSheet.objects.get(id=data.get('row')[0]).chart_id
            if (data.get('action') == "REBUTTAL") and (chart.status not in ['QA REBUTTAL','CLIENT REBUTTAL']):
                if request.user.role == "CLIENT":
                    chart.status = "CLIENT REBUTTAL"
                    create_notification(f"@ submitted a rebuttal", request.user, CqUser.objects.filter(role__in=['QA', 'MANAGER'], is_active=True, is_deleted=False), 'CLIENT REBUTTAL', chart)
                else:
                    chart.status = 'QA REBUTTAL'
                    create_notification(f"@ submitted a rebuttal to {chart.auditor.first_name} {chart.auditor.last_name}", request.user, [chart.auditor], 'QA REBUTTAL', chart)
                chart.urgent_flag = True
                chart.save()
            obj = AuditSheetComment(
                    chart = chart,
                    audit_sheet_rows = data.get('row'),
                    audit_sheet_columns = data.get('column'),
                    user = request.user,
                    tagged_user = data.get('tagged_user'),
                    comment = data.get('comment'),
                    updated_at = data.get('modified_at') if data.get('modified_at') else datetime.now(),
                    action = data.get('action')
                    )
            objects.append(obj)
        AuditSheetComment.objects.bulk_create(objects)
        return Response({"message":'All activity saved successfully'}, status=status.HTTP_201_CREATED) 


class AuditSheetHealthSystemViewSet(SerializerClassMixin, ListModelMixin, viewsets.GenericViewSet):
    queryset = HealthSystem.objects.filter(is_active=True, is_deleted=False)
    serializer_class = AuditSheetHealthSystemSerializer
    permission_classes = (permissions.IsAuthenticated,)
    serializer_action_classes ={
        'hospitals': AuditSheetHospitalSerializer,
        'specialty': AuditSheetDepartmentSerializer
    }

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset()).order_by('id')

        if health_system_id := request.query_params.get('health_system_id'):
            queryset = Hospital.objects.filter(health_system__id=health_system_id, is_active=True, is_deleted=False)

        if hospital_id := request.query_params.get('hospital_id'):
            queryset = Department.objects.filter(hospital__id=hospital_id, is_active=True, is_deleted=False)

        if specialty := request.query_params.get('specialty'):
            queryset = Department.objects.filter(id=specialty, is_active=True, is_deleted=False)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='hospitals', permission_classes=[permissions.IsAuthenticated],)
    def hospitals(self, request, pk=None):
        queryset = Hospital.objects.filter(is_active=True, is_deleted=False)

        '''
        Need to confirm for reverse filtering
        if health_system_id := request.query_params.get('health_system_id'):
            queryset = HealthSystem.objects.filter(id=health_system_id, is_active=True, is_deleted=False)'''

        if hospital_id := request.query_params.get('hospital_id'):
            queryset = Department.objects.filter(hospital__id=hospital_id, is_active=True, is_deleted=False)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='specialty', permission_classes=[permissions.IsAuthenticated],)
    def specialty(self, request, pk=None):
        queryset = Department.objects.filter(is_active=True, is_deleted=False)

        ''' 
        Need to confirm for reverse filtering
        if health_system_id := request.query_params.get('health_system_id'):
            queryset = HealthSystem.objects.filter(id=health_system_id, is_active=True, is_deleted=False)

        if hospital_id := request.query_params.get('hospital_id'):
            queryset = Department.objects.filter(hospital__id=hospital_id, is_active=True, is_deleted=False)'''

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ListUsersViewset(viewsets.ModelViewSet):
    queryset = CqUser.objects.filter(is_active=True, is_deleted=False)
    serializer_class = ListUsersSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def list(self, request):
        queryset = self.get_queryset()
        if request.user.role == "AUDITOR":
            queryset = queryset.exclude(role='CLIENT')

        elif request.user.role =="CLIENT":
            queryset = queryset.filter(role="MANAGER")

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)