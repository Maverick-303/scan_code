import io
import logging
import urllib

from django.contrib.postgres.fields import JSONField
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.db import models
from django.template.loader import get_template
from model_utils.models import TimeStampedModel

from leads.models import Lead
from utils.AWS import AwsConnection


class CiBilReport(TimeStampedModel):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    lead = models.ForeignKey(Lead, on_delete=models.SET_NULL, related_name="cibil_credit_report", null=True)
    pan = models.CharField(max_length=30, blank=True, null=True)
    pcc = models.CharField(max_length=150, blank=True, null=True, help_text="unique id for oto-customer-pan")
    report_json = JSONField(default=dict)
    # in UTC
    control_number = models.CharField(max_length=50, blank=True, null=True, help_text="cibil control number")
    report_timestamp = models.DateTimeField(default=None, null=True, blank=True)
    score = models.IntegerField(default=None, null=True, blank=True)
    status = models.CharField(max_length=50, blank=True, null=True, help_text="status of cibil report")
    html_report_s3 = models.CharField(max_length=200, blank=True, null=True, help_text="html_report s3")
    is_active = models.BooleanField(default=True)

    def get_html_report(self):
        """ this function returns html string from sc=3 or from json"""
        from credit_reports.cibil.cibil_report import CibilReport
        assert self.report_json, "Cibil Report Json Not Found"
        cj = CibilReport(self.report_json)
        context_data = {
            "meta": cj.report_meta(),
            "report_summary": cj.report_summary(),
            "credit_accounts_details": cj.credit_account_information(),
            "credit_accounts_details_active": cj.credit_account_information_byfurgation()["active"],
            "credit_accounts_details_closed": cj.credit_account_information_byfurgation()["closed"],
            "report_inquiry_information": cj.get_report_inquiry_information(),
            "dpd_calender": cj.dpd_calender(),
        }
        template_name = "cibil_report_template.html"
        template = get_template(template_name)
        # Render template with context data
        html = template.render(context=context_data)
        html_dtring = html.encode("utf-8")
        return html_dtring

    def sync_to_s3(self):
        """this function will sync html report to s3 in html file"""
        try:
            file_name = f"{self.lead_id}-{self.pan}-{self.control_number}-{self.modified.date()}.html"
            aws = AwsConnection()
            io_file = io.BytesIO(self.get_html_report())
            rar_file = InMemoryUploadedFile(
                file=io_file,
                field_name=None,  # not sure about this field
                size=len(io_file.getvalue()),
                name=file_name,
                content_type="text/html",
                charset=None,  # not sure about this field
            )
            key = f"{get_env_value()}/CreditReport/CIBIL/{rar_file.name}"
            aws.upload_s3_object_private(key=key, file=rar_file)
            # not sure why we are storing link here in this formate
            s3_link = aws.get_path(key=key)
            a = CiBilReport.objects.get(id=self.id)
            a.html_report_s3 = s3_link
            self.html_report_s3 = s3_link
            self.save()
            a.save()
            return self
        except Exception as e:
            logging.error(e, exc_info=True)
            pass

    def get_presigned_s3_link(self):
        parser_url = urllib.parse.urlparse(self.html_report_s3)
        # noticed that not all documents links are from s3
        # this function will only handle documents links from s3
        # splited from s3.amazonaws.com instead of . to check for s3 abjects
        bucket = parser_url.netloc.split('.s3.')[0]
        keypath = parser_url.path[1:]
        s3_link = AwsConnection().generate_pre_signed_url(key=keypath, bucket=bucket)
        return s3_link

    def get_s3_html_link(self):
        # if not it syncs and retuns the link
        if not self.html_report_s3:
            self.sync_to_s3()
        return self.get_presigned_s3_link()





    def get_html_content(self) -> bytes:
        parser_url = urllib.parse.urlparse(self.html_report_s3)
        # noticed that not all documents links are from s3
        # this function will only handle documents links from s3
        # splited from s3.amazonaws.com instead of . to check for s3 abjects
        bucket = parser_url.netloc.split('.s3.')[0]
        keypath = parser_url.path[1:]
        s3_obj = AwsConnection().get_s3_object(key=keypath, bucket=bucket)
        # this function will return all the documents content in bytes format
        return s3_obj['Body'].read()

    def generate_pdf_file_from_s3(self):
        options = {"orientation": "Portrait",
                                   "page-size":"A4",
                                   "quiet": ""
                                   }
        if not self.html_report_s3:
            self.sync_to_s3()
        inline_pdf = PDFGenerator(options=options).generate_pdf(input_str=self.get_html_content().decode())
        return inline_pdf

    def encrypted_pdf_file(self):
        import PyPDF2
        password = self.pan.upper()
        """password will be upper case of pan"""
        import io
        pdf_reader = PyPDF2.PdfFileReader(io.BytesIO(self.generate_pdf_file_from_s3()))
        pdf_writer = PyPDF2.PdfFileWriter()

        for page_num in range(pdf_reader.numPages):
            pdf_writer.addPage(pdf_reader.getPage(page_num))
        pdf_writer.encrypt(password)
        encrypted_file = io.BytesIO()
        pdf_writer.write(encrypted_file)
        encrypted_file.seek(0)
        return encrypted_file

    def send_encrypted_file_as_email(self):
        msg = MIMEMultipart()
        msg["Subject"] = " Your CIBIL Credit Score"
        file_name = f"Cibil_Report_{self.control_number}_XXXXXX{self.pan[-4:]}.pdf"

        email_to = [self.lead.account.email]
        body = f"""Dear {self.lead.account.full_name},

We're delighted, As you have taken the right step by accessing your CIBIL credit report.
Your CIBIL report {self.control_number} through one of our partner, OTO.
To open the PDF, please enter the password, the password would be your PAN number in the upper case.

You can reach out to your partner on +919372081131 or support@otocapital.in

This email and any files transmitted with it are confidential and intended solely for the use of the addressee(s). If you have erroneously received this message, please immediately delete this email from your system and notify the sender by reply Email. Also, if you are not the intended recipient, you are hereby notified that any disclosure, copying, distribution or taking any action in reliance on the contents of this message/information is strictly prohibited and unlawful. Any views or opinions presented in this email are solely those of the author and do not necessarily represent those of the organization. Electronic messages are not secure or error free and can contain viruses or may be delayed, the organization and/or sender is not liable for any of these occurrences. Further the organization and the sender have no responsibility for unauthorized access and/or alteration of this communication, nor for any consequences based on or arising from your use of information that may have been illegitimately accessed or altered."""
        msg.attach(MIMEText(body))
        pdf_attachment = MIMEApplication(self.encrypted_pdf_file().read())
        pdf_attachment.add_header(
            "Content-Disposition",
            "attachment",
            filename=file_name,
        )
        pdf_attachment.add_header("Content-Type", f'{"application/pdf"}; charset=UTF-8')

        msg.attach(pdf_attachment)

        return AwsConnection().send_email(body=msg, email_to=email_to)

    class Meta:
        db_table = "cibil_report"

    @property
    def is_expired(self) -> bool:
        """this function will return whether this report is expired"""
        if self.report_json in ['{}', {}]:
            return True
        if not self.report_timestamp:
            return True
        utc_now = datetime.utcnow()
        report_age = utc_now.date() - self.report_timestamp.date()
        return not report_age.days < 90 # days

    @property
    def cibil_report_link(self):
        from credit_reports.cibil.Apis import CiBilGetProductWebToken
        return CiBilGetProductWebToken(pan=self.pan)()

    def get_report(self):
        if self.is_expired:
            from credit_reports.cibil.Apis import CiBilGetCustomerAssets
            report_json, score, report_timestamp, control_number = CiBilGetCustomerAssets(pan=self.pan)()
            return {
            "score": score,
            "json": report_json,
            "control_number": control_number,
            "report_timestamp": report_timestamp,
        }

        return {
            "score": self.score,
            "json": self.report_json,
            "control_number": self.control_number,
            "report_timestamp": self.report_timestamp,
        }

    def update_lead_log(self):
        CiBilReportLeadLogs.objects.create(lead=self.lead_id, pan=self.pan, report_json=self.report_json,
                                           report_timestamp=self.report_timestamp, score=self.score,
                                           control_number=self.control_number, status=self.status,
                                           html_report_s3=self.html_report_s3, pcc=self.pcc)


class CiBilReportLogs(TimeStampedModel):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    url = models.URLField(null=True)
    method = models.CharField(max_length=10, null=True, blank=True)
    request = JSONField(default=dict)
    response = JSONField(default=dict)
    status = models.CharField(max_length=50, blank=True, null=True, help_text="status of cibil report")
    status_code = models.BigIntegerField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "cibil_report_logs"


class CiBilReportAuthLogs(TimeStampedModel):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    cibil = models.ForeignKey(CiBilReport, on_delete=models.SET_NULL, related_name="cibil_auth", null=True)
    challenge_config_guid = models.CharField(
        max_length=50, blank=True, null=True, help_text="auth challenge_config_guid"
    )
    question_key = models.CharField(max_length=50, blank=True, null=True, help_text="auth answer choice")
    answer = models.TextField(blank=True, null=True, help_text="user answer")
    question = models.TextField(blank=True, null=True, help_text="question text")
    answer_choice = models.CharField(max_length=50, blank=True, null=True, help_text="auth answer choice")
    resend_eligible = models.BooleanField(
        default=False, help_text="User need to try Resend OTP only when resendeligible is true in response"
    )
    resend_otp = models.BooleanField(
        default=False,
        help_text="Customer can submit the resendOTP tag as true if  GetAuthentication Response resendeligible is true",
    )
    status = models.CharField(max_length=50, blank=True, null=True, help_text="status of cibil auth")
    auth_queue = models.CharField(max_length=50, blank=True, null=True, help_text="auth Queue")
    skip_eligible = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "cibil_auth_log"

    @property
    def is_question_expired(self):
        """time limit to 9 min"""
        created = self.created.astimezone()
        now = datetime.now().astimezone()
        expired_time = now + timedelta(minutes=-9)
        return expired_time >= created

class CiBilReportLeadLogs(TimeStampedModel):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    lead = models.IntegerField(default=0)
    pan = models.CharField(max_length=30, blank=True, null=True)
    pcc = models.CharField(max_length=150, blank=True, null=True, help_text="unique id for oto-customer-pan")
    report_json = JSONField(default=dict)
    # in UTC
    control_number = models.CharField(max_length=50, blank=True, null=True, help_text="cibil control number")
    report_timestamp = models.DateTimeField(default=None, null=True, blank=True)
    score = models.IntegerField(default=None, null=True, blank=True)
    status = models.CharField(max_length=50, blank=True, null=True, help_text="status of cibil report")
    html_report_s3 = models.CharField(max_length=200, blank=True, null=True, help_text="html_report s3")
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "cibil_report_lead_logs"



import requests
from rest_framework.response import Response
from rest_framework.views import APIView

from utils.api import production_env, get_env_value


class ExpProxy:
    def __init__(self):
        ...

    proxy_url = 'https://devapi.otocapital.in/api/v1/bureau/proxy/'
    if production_env():
        proxy_url = 'https://prodapi.otocapital.in/api/v1/bureau/proxy/'

    def __call__(self, url, data=None, headers=None, method='POST'):
        mock_request = requests.models.Response()
        _data = {
            "url": url,
            "headers": headers,
            "method": method,
            "data": data

        }
        proxy_response = requests.request(method=method, url=self.proxy_url, json=_data, headers={"Content-Type": 'application/json'})
        mock_request.status_code = proxy_response.json()['status_code']
        mock_request._content = proxy_response.json()['data'].encode('utf-8')
        return mock_request


class ExpProxyView(APIView):

    def post(self, request, *args, **kwargs):
        url = request.data['url']
        data = request.data['data']
        headers = request.data['headers']
        method = request.data['method']
        response = requests.request(method=method, url=url, json=data, headers=headers,
                                    cert=('/home/ubuntu/oto_directory/oto_project/credit_reports/cibil_ssl/otocapital.in.crt', '/home/ubuntu/oto_directory/oto_project/credit_reports/cibil_ssl/pwddevapi.otocapital.in.key'))
        data = {
            "data": response.text,
            "status_code": response.status_code
        }
        return Response(data)
