from django.db import models
from cqdashboard.models import Chart
from cqusers.models import CqUser
from cqclient.models import Client
from codequick.fields import S3PrivateFileField
import datetime


def current_year():
    return datetime.date.today().year


class Industry(models.Model):
    year = models.PositiveIntegerField(default=current_year(),null=False)
    code = models.CharField(max_length=200, null=False)
    choice = (
                    ("CPT", "CPT"),
                    ("ICD", "ICD"),
                    ("E&M", "E&M"),
                    )
    type = models.CharField(max_length = 200,
                            choices = choice,
                            default = 'CPT')

    modifier = models.CharField(max_length =200,null=True)
    par_amount = models.FloatField(null=False)
    non_par_amount = models.FloatField(null=False)
    limiting_charge_amount = models.FloatField(null=False)

    def __str__(self):
        return self.code

    class Meta:
        unique_together = ['year', 'code', 'modifier']
        db_table = 'industry'


class AuditSheet(models.Model):
    chart_id = models.ForeignKey(Chart, null=False, related_name='reference_chart', on_delete=models.CASCADE)
    index = models.IntegerField(null=False)
    sheet_name = models.CharField(max_length=200, null=False,)
    row_id = models.IntegerField(null=False)
    encounter_no = models.CharField(max_length=200, null=True, blank=True)
    rendering = models.ForeignKey(Client, null=True, blank=True, related_name='provider_auditsheet', on_delete=models.CASCADE)
    enc_dt = models.DateField(null=True, blank=True)
    srvcs_no = models.CharField(max_length=200, null=True, blank=True)
    provider_rvu = models.FloatField(null=True, blank=True)
    provider_dollar_value = models.FloatField(null=True, blank=True)
    response = models.CharField(max_length=200, null=True, blank=True)
    agree = models.BooleanField(null=True, blank=True)
    disagree = models.BooleanField(null=True, blank=True)
    audited_code = models.CharField(max_length=200, null=True, blank=True)
    audited_rvu = models.FloatField(null=True, blank=True)
    audited_dollar_value = models.FloatField(null=True, blank=True)
    notes = models.TextField(null=True, blank=True)

    class Meta:
        db_table ="auditsheet"


class AuditHoursMonitor(models.Model):
    chart_id = models.ForeignKey(Chart, related_name='audit_chart', on_delete=models.CASCADE)
    user = models.ForeignKey(CqUser, related_name='audit_hours_user', on_delete=models.CASCADE)
    audit_start_time = models.DateTimeField()
    audit_end_time = models.DateTimeField()
    recent_audit_snaps = S3PrivateFileField(
        "Recent Audits",
        help_text="Upload Chart",
        upload_to="media/audit_snapshots/",
        max_length=254,
        null=True,
        blank=True,
        # validators=[FileExtensionValidator(['pdf', 'hl7', 'doc', 'docx', 'xls', 'xlsx'])],
    )

    def __str__(self):
        return f"{self.chart_id} - {self.user.first_name}"

    class Meta:
        db_table = 'audit_hours_monitor'


class AuditSheetMetric(models.Model):
    chart_id = models.ForeignKey(Chart, related_name='audit_metric_chart', on_delete=models.CASCADE)
    provider = models.ForeignKey(Client, related_name='auditsheet_provider', on_delete=models.CASCADE)
    modifier = models.FloatField()
    modifier_percentage = models.FloatField()
    documentation = models.FloatField(null=True)
    upcoded = models.FloatField()
    upcoded_percentage = models.FloatField()
    downcoded = models.FloatField()
    downcoded_percentage = models.FloatField()
    diagnosis_specificity = models.FloatField(null=True)
    rvu = models.FloatField()
    rvu_percentage = models.FloatField()
    cq_score = models.FloatField()
    outstanding_revenue = models.FloatField()

    def __str__(self):
        return f"{self.chart_id} - {self.provider}" 

    class Meta:
        db_table = 'auditsheetmetric'

class AuditSheetComment(models.Model):
    CHOICES = (('OPEN', 'OPEN'), ('RESOLVED', 'RESOLVED'), ('ADD', 'ADD'), ('UPDATE', 'UPDATE'), ('DELETE', 'DELETE'), ('REBUTTAL', 'REBUTTAL'), ('RE-OPENED', 'RE-OPENED'), ('REBUTTAL-RESOLVED', 'REBUTTAL-RESOLVED'), ('BATCH NOTES', 'BATCH NOTES'))
    chart = models.ForeignKey(Chart, related_name='chart_comment', on_delete=models.CASCADE)
    parent = models.ForeignKey('self', related_name='auditsheet_comment', on_delete=models.CASCADE, null=True, blank=True)
    audit_sheet_rows = models.JSONField(null=True, blank=True)
    audit_sheet_columns = models.JSONField(null=True, blank=True)
    user = models.ForeignKey(CqUser, related_name='user_comment', on_delete=models.CASCADE)
    tagged_user = models.JSONField(null=True, blank=True)
    comment = models.TextField(null=True, blank=True)
    commented_at = models.DateTimeField(auto_now=True)
    updated_at = models.DateTimeField(auto_now_add=True)
    action = models.CharField(max_length=256, choices=CHOICES, default='OPEN')

    def __str__(self):
        return f"{self.chart} - {self.id}"

    class Meta:
        db_table = 'auditsheetcomment'