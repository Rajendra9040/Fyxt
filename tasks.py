from django.core.files import File
from djangoconvertvdoctopdf.convertor import StreamingConvertedPdf, ConvertFileModelField


#Convert Doc or Docx to PDF:
def docx_to_pdf(file):
    inst = ConvertFileModelField(file)
    r_file = inst.get_content()
    doc_obj = File(open(r_file.get('path'), 'rb'))
    return doc_obj


from cqclient.models import Hospital, Department


# Department Spocs for Urgency_email:
def get_department(chart):

    if chart.client.user_type == 'HEALTH SYSTEM':
        return None

    elif chart.client.user_type in ['PHYSICIANS GROUP', 'HOSPITAL']:
        try:
            hospital = Hospital.objects.filter(spoc=chart.client, is_active=True, is_deleted=False).first()
        except:
            return None

    elif chart.client.user_type == 'DEPARTMENT':
        try:
            hospital = Department.objects.filter(spoc=chart.client, is_active=True, is_deleted=False).first().hospital
        except:
            return None

    elif chart.client.user_type == 'PROVIDER':
        try:
            hospital = Department.objects.filter(providers=chart.client, is_active=True, is_deleted=False).first().hospital
        except:
            return None

    department = Department.objects.filter(hospital=hospital, specialty=chart.specialty, is_active=True, is_deleted=False).first()
    return department
