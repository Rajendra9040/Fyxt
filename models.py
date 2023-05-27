from django.db import models
from django.core.validators import FileExtensionValidator

from codequick.fields import S3PrivateFileField

from cqclient.models import Client
from cqusers.models import CqUser, Specialty, CqTeam


class Chart(models.Model):
    batch_id = models.IntegerField(null=True, blank=True)
    chart_id = models.CharField(unique=True, max_length=254, editable=False)
    parent_chart = models.ForeignKey('self', on_delete=models.CASCADE, related_name="split_chart", null=True, blank=True)
    upload_date = models.DateTimeField(auto_now_add=True, blank=False)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    specialty = models.ForeignKey(Specialty, on_delete=models.CASCADE, related_name="chart_specialty", blank=True, null=True)
    CHOICES = (
        ('ON HOLD', 'ON HOLD'),
        ('AWAITING AUDIT', 'AWAITING AUDIT'),
        ('IN PROGRESS', 'IN PROGRESS'),
        ('IN REVIEW', 'IN REVIEW'),
        ('AWAITING REVIEW', 'AWAITING REVIEW'),
        ('ARCHIVED', 'ARCHIVED'),
        ('AWAITING ASSIGNMENT', 'AWAITING ASSIGNMENT'),
        ('QA REBUTTAL', 'QA REBUTTAL'),
        ('CLIENT REBUTTAL', 'CLIENT REBUTTAL'),
    )
    status = models.CharField(blank=False,null=False,max_length=254,choices=CHOICES, default='AWAITING ASSIGNMENT')
    last_updated_date = models.DateTimeField(auto_now=True)
    auditor = models.ForeignKey(CqUser, on_delete=models.CASCADE, related_name='cq_auditor_user', blank=True, null=True)
    qa = models.ForeignKey(CqUser, on_delete=models.CASCADE, related_name='cq_qa_user', blank=True, null=True)
    upload_chart = models.FileField()
    # total_pages = models.CharField(max_length=254, null=True, blank=True, default="0")
    total_pages = models.CharField(max_length=254, default="0")
    offline_upload_flag = models.BooleanField(default=False)
    urgent_flag = models.BooleanField(default=False)
    audited_date = models.DateTimeField(null=True, blank=True)
    archived_date = models.DateTimeField(null=True, blank=True)
    rebuttal_date = models.DateTimeField(null=True, blank=True)
    is_split = models.BooleanField(default=False)
    chart_updated_date = models.DateTimeField(null=True, blank=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.chart_id}-{self.client.user.first_name}-{self.client.user.last_name}"

    class Meta:
        db_table = 'chart'
    # chard id,client fname,lname


class ChartUpload(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    uploaded_date = models.DateTimeField(auto_now=True,blank=False)
    upload_chart = S3PrivateFileField(
        "Chart File",
        help_text="Upload Chart",
        # upload_to='charts',
        max_length=254,
        null=True,
        blank=True,
        # validators=[FileExtensionValidator(['pdf', 'hl7', 'doc', 'docx', 'xls', 'xlsx'])],
    )
    total_pages = models.CharField(max_length=254, default="0")
    
    def __str__(self):
        return f"{self.client.user.first_name} {self.client.user.last_name}"

    class Meta:
        db_table = 'chartupload'

class ChartHistory(models.Model):
    user = models.ForeignKey(CqUser, on_delete=models.CASCADE, related_name = 'assigned_user')
    chart = models.ForeignKey(Chart, on_delete=models.CASCADE, related_name = 'assigned_chart')
    assigned_date = models.DateField(auto_now=True)
    CHOICES = (
                ('AUDITOR', 'AUDITOR'),
                ('QA', 'QA'),
            )
    user_type = models.CharField(blank=False, max_length=254, choices=CHOICES)

    def __str__(self):
        return self.user

    class Meta:
        db_table = 'charthistory'