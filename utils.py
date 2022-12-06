from .models import AuditSheet, AuditSheetMetric
from cqclient.models import ProviderStatistics, Client
from cqdashboard.models import Chart
from django.db.models import F, Q, Avg, Sum

# def calculate_audit_metrics(Chart_id):
#     total_auditsheet_queryset = AuditSheet.objects.filter(chart_id=Chart_id)
#     auditsheet_queryset = total_auditsheet_queryset.filter(disagree=True).annotate(rvu_diff = F("audited_rvu") - F("provider_rvu"))
#     total_object_count = total_auditsheet_queryset.count()
#     if total_object_count == 0:
#         return 
#     upcoded = auditsheet_queryset.filter(rvu_diff__gt =0).count()
#     downcoded = auditsheet_queryset.filter(rvu_diff__lt =0).count()
#     rvu = upcoded + downcoded #chart_queryset.filter(~Q(rvu_diff=0)).count()
#     modifier = auditsheet_queryset.filter(~Q(srvcs_no__contains ='-'), Q(audited_code__contains ='-')).count()
#     upcoded_percentage = round((1 - (upcoded/total_object_count))*100)
#     downcoded_percentage = round((1 - (downcoded/total_object_count))*100)
#     rvu_percentage = round((1 - (rvu/total_object_count))*100)
#     modifier_percentage = round((1 - (modifier/total_object_count))*100)
#     cq_score = round((upcoded_percentage + downcoded_percentage + rvu_percentage + modifier_percentage)/4) 
#     provider = Client.objects.get(id=2)
#     AuditSheetMetric.objects.update_or_create(
#         defaults = {
#             "upcoded": upcoded,
#             "upcoded_percentage": upcoded_percentage,
#             "downcoded": downcoded,
#             "downcoded_percentage": downcoded_percentage,
#             "rvu": rvu,
#             "rvu_percentage": rvu_percentage,
#             "modifier": modifier,
#             "modifier_percentage": modifier_percentage,
#             "cq_score": cq_score,
#             "provider": provider,
#         },
#         chart_id = Chart.objects.get(id=Chart_id),         
#     )
#     return 

def calculate_audit_metrics(chart_id):
    total_auditsheet_queryset = AuditSheet.objects.filter(chart_id=chart_id)
    providers = total_auditsheet_queryset.values_list("rendering",flat=True).distinct()
    for provider in providers:
        if provider != None:
            provider_auditsheet = total_auditsheet_queryset.filter(rendering=provider).annotate(outstanding_revenue=F("audited_dollar_value")-F("provider_dollar_value"))
            provider_auditsheet_disagree = provider_auditsheet.filter(disagree=True).annotate(rvu_diff = F("audited_rvu") - F("provider_rvu"))
            provider_auditsheet_total_count = provider_auditsheet.count()
            if provider_auditsheet_total_count == 0:
                continue
            upcoded = provider_auditsheet_disagree.filter(rvu_diff__gt =0).count()
            downcoded = provider_auditsheet_disagree.filter(rvu_diff__lt =0).count()
            rvu = upcoded + downcoded #chart_queryset.filter(~Q(rvu_diff=0)).count()
            modifier = provider_auditsheet_disagree.filter(~Q(srvcs_no__contains ='-'), Q(audited_code__contains ='-')).count()
            upcoded_percentage = round((1 - (upcoded/provider_auditsheet_total_count))*100)
            downcoded_percentage = round((1 - (downcoded/provider_auditsheet_total_count))*100)
            rvu_percentage = round((1 - (rvu/provider_auditsheet_total_count))*100)
            modifier_percentage = round((1 - (modifier/provider_auditsheet_total_count))*100)
            cq_score = round((upcoded_percentage + downcoded_percentage + rvu_percentage + modifier_percentage)/4)
            provider_outstanding_revenue = round(provider_auditsheet.aggregate(Sum("outstanding_revenue")).get("outstanding_revenue__sum",0),2)
            _provider = Client.objects.get(id=provider)

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
                                        "cq_score": cq_score,
                                        "outstanding_revenue": provider_outstanding_revenue
                                    },
                                    chart_id = Chart.objects.get(id=chart_id),
                                    provider =  _provider,         
                                )
    return 


def provider_cq_score(provider):
    charts = Chart.objects.filter(status='ARCHIVED', is_deleted=False, client=provider)
    avg = AuditSheetMetric.objects.filter(chart_id__in =charts).aggregate(Avg('cq_score'))['cq_score__avg']
    cq_score = avg if avg else 0
    return cq_score

def get_provider_rank(provider_user_list, provider_id):
    #total_provider = list(ProviderStatistics.objects.filter(provider__user__id__in=provider_user_list).values_list("provider", flat=True).distinct().order_by("-cq_score"))
    total_provider = list(AuditSheetMetric.objects.filter(provider__user__id__in=provider_user_list).values_list("provider", flat=True).distinct().annotate(Avg("cq_score")).order_by("-cq_score__avg"))
    try:
        rank = total_provider.index(int(provider_id))+1
    except:
        rank = None
    provider_rank = {"rank":rank, "total_provider":len(total_provider)}
    return provider_rank  
    