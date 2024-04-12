import distutils
import logging
import uuid

from django.conf import settings
from django.db import transaction

from credit_reports.mod_diffs import (
    CiBilReport,
    CiBilReportAuthLogs,
    CiBilReportLogs
)
from credit_reports.proxy.proxy import ExpProxy

logger = logging.getLogger(__name__)


class CiBilApi:
    # CIBIL BASE URLS
    CIBIL_CRED = settings.CIBIL_CRED
    BASE_URL = CIBIL_CRED["BASE_URL"]
    BASE_URL_REPORT = CIBIL_CRED["BASE_URL_REPORT"]

    # product configs
    ProductConfigurationId = "OTO01"
    SiteName = "1T9TchPvtLtd"
    AccountName = CIBIL_CRED["ACCOUNT_NAME"]
    AccountCode = CIBIL_CRED["ACCOUNT_CODE"]
    MemberRefId = "DTC Partner"
    ApiKey = CIBIL_CRED["API_KEY"]

    # headers
    HEADERS = {
        "Content-Type": "application/json",
        "apikey": ApiKey,
        "Accept": "application/json",
        "member-ref-id": MemberRefId,
    }

    AccountConfig = {
        "ProductConfigurationId": ProductConfigurationId,
        "SiteName": SiteName,
        "AccountName": AccountName,
        "AccountCode": AccountCode,
    }

    def connect(
        self, path: str, method: str, params: dict = {}, data: bytes = None, json: dict = {}, headers: dict = None
    ):
        log_obj = CiBilReportLogs()
        log_obj.url = f"{self.BASE_URL}{path}"
        log_obj.request = json
        log_obj.method = method

        try:
            req_data = {"url": f"{self.BASE_URL}{path}", "method": method, "params": params, "headers": headers}
            res = ExpProxy()(url=req_data["url"], data=json, headers=self.HEADERS, method=method)
            # res = requests.request(
            #     method=method,
            #     url=req_data["url"],
            #     json=json,
            #     headers=self.HEADERS,
            #     cert=(
            #         "/home/ubuntu/oto_directory/oto_project/credit_reports/cibil_ssl/otocapital.in.crt",
            #         "/home/ubuntu/oto_directory/oto_project/credit_reports/cibil_ssl/pwddevapi.otocapital.in.key",
            #     )
            # )

            res.raise_for_status()
            log_obj.response = res.json()
            log_obj.status_code = res.status_code
            log_obj.save()
            return res.json()
        except Exception as e:
            log_obj.response = {"ERROR": e.__str__()}
            log_obj.status_code = res.status_code if res else 500
            log_obj.save()
            logging.error(e, exc_info=True)
            ...

    def id_mask(self, refid: str = None) -> str:
        # oto need to tag each customer with unique reference id  for each customer
        # for the we simple masked the incoming id with encoding that will consistent with flow
        return refid.__str__().upper().encode().hex().__str__()


class CiBilPing(CiBilApi):
    PATH = "consumer/dtc/v4/ping"

    def __init__(self):
        self.data = {
            "PingRequest": {
                "ClientKey": super().id_mask(),
                "RequestKey": uuid.uuid4().hex.__str__(),
            }
        }
        self.data["PingRequest"].update(self.AccountConfig)

    def __call__(self, data=None, *args, **kwargs):
        response = super().connect(path=self.PATH, method="POST", json=self.data)
        return response


class CiBilFulFillOffer(CiBilApi):
    PATH = "consumer/dtc/v4/fulfilloffer"

    def __init__(
        self,
        pan: str,
        first_name: str = "",
        last_name: str = "",
        address: str = "",
        city: str = "",
        pincode: str = "",
        state: str = "",
        dob: str = "",
        ph: str = "",
        email: str = "",
        gender: str = "Male",
        lead_id: int = None,
    ):
        self.pan = pan
        self.pcc = super().id_mask(refid=pan)
        self.cb, _ = CiBilReport.objects.update_or_create(
            pan=self.pan.upper(), defaults={"pcc": self.pcc, "lead_id": lead_id}
        )
        self.data = {
            "FulfillOfferRequest": {
                "ClientKey": self.pcc,
                "RequestKey": uuid.uuid4().__str__(),
                "PartnerCustomerId": self.pcc,
                "CustomerInfo": {
                    "Name": {"Forename": first_name, "Surname": last_name},
                    "IdentificationNumber": {"IdentifierName": "TaxId", "Id": pan},
                    "Address": {
                        "StreetAddress": address,
                        "City": city,
                        "PostalCode": pincode,
                        "Region": state,
                        "AddressType": 1,
                    },
                    "DateOfBirth": dob,
                    "PhoneNumber": {"Number": ph},
                    "Email": email,
                    "Gender": gender,
                },
                "LegalCopyStatus": "Accept",
                "UserConsentForDataSharing": True,
            }
        }
        self.data["FulfillOfferRequest"].update(self.AccountConfig)

    def get_report(self):

        return {
            "score": self.cb.score,
            "url": "CiBilGetProductWebToken(pan=self.pan)()",
            "report": self.cb.report_json,
        }

    def __call__(self, *args, **kwargs):
        try:
            application_status = None
            if self.cb.status in ["Success"]:
                return self.cb.status
            response = super().connect(path=self.PATH, method="POST", json=self.data)
            response_status = response["FulfillOfferResponse"]["ResponseStatus"]
            if response_status in ["Success"]:
                application_status = response["FulfillOfferResponse"]["FulfillOfferSuccess"]["Status"]
                if application_status in ["Success"]:
                    self.cb.status = application_status
                    self.cb.save()
                    (
                        self.cb.report_json,
                        self.cb.score,
                        self.cb.report_timestamp,
                        self.cb.control_number,
                    ) = CiBilGetCustomerAssets(pan=self.pan)()
                    self.cb.save()
            else:
                application_status = response["FulfillOfferResponse"]["FulfillOfferError"]["Failure"]["FailureEnum"]
            self.cb.status = application_status
            self.cb.save()
            if application_status in ["Pending", "InProgress"]:
                application_status = "Pending"
            return application_status
        except Exception as e:
            logging.error(e, exc_info=True)
            return "Failure"


class CiBilGetAuthenticationQuestions(CiBilApi):
    PATH = "consumer/dtc/v4/GetAuthenticationQuestions"

    def __init__(self, pan: str):
        self.pcc = super().id_mask(refid=pan)
        self.pan = pan
        self.cb = CiBilReport.objects.filter(pan=pan.upper(), pcc=self.pcc).last()
        assert self.cb, "Cibil Application Fulfill Not Found"
        self.unverified_auth = self.cb.cibil_auth.filter().exclude(status="Success").last()
        self.data = {
            "GetAuthenticationQuestionsRequest": {
                "ClientKey": self.pcc,
                "RequestKey": uuid.uuid4().__str__(),
                "PartnerCustomerId": self.pcc,
            }
        }
        self.data["GetAuthenticationQuestionsRequest"].update(self.AccountConfig)

    def __call__(self, *args, **kwargs):
        # if self.unverified_auth:
        #     if not self.unverified_auth.is_question_expired:
        #         return {"question": self.unverified_auth.question,
        #                 "challenge_guid": self.unverified_auth.challenge_config_guid,
        #                 "status": self.unverified_auth.status}
        response = super().connect(path=self.PATH, method="POST", json=self.data)
        if response["GetAuthenticationQuestionsResponse"]["ResponseStatus"] in ["Success"]:
            auth = response["GetAuthenticationQuestionsResponse"]["GetAuthenticationQuestionsSuccess"]
            challenge_config_guid = auth["ChallengeConfigGUID"]
            status = auth.get("IVStatus", "Pending")
            if status in ["Pending", "InProgress"]:
                status = "Pending"
            if status in ["Success"]:
                self.cb.cibil_auth.create(challenge_config_guid=challenge_config_guid, status=status)
                self.cb.status = status
                self.cb.save()
                return {
                    "question": " ",
                    "challenge_guid": challenge_config_guid,
                    "status": status,
                    "resend_eligible": False,
                    "skip_eligible": False,
                }
            if isinstance(auth.get("question"), list):
                return {
                    "question": "question",
                    "challenge_guid": "challenge_config_guid",
                    "status": "Failure",
                    "resend_eligible": False,
                    "skip_eligible": False,
                }
            question_dict = auth.get("question", {})
            answer_choice_dict = question_dict.get("AnswerChoice")
            answer_choice = answer_choice_dict.get("AnswerChoiceId")
            question = question_dict.get("FullQuestionText")
            question_key = question_dict.get("Key")
            queue_name = auth.get("QueueName")
            resend_eligible = question_dict.get("resendEligible")
            skip_eligible = question_dict.get("skipEligible")
            auth = self.cb.cibil_auth.create(
                challenge_config_guid=challenge_config_guid,
                status=status,
                question_key=question_key,
                question=question,
                answer_choice=answer_choice,
                auth_queue=queue_name,
                resend_eligible=resend_eligible,
                skip_eligible=skip_eligible,
            )

            return {
                "question": question,
                "challenge_guid": challenge_config_guid,
                "status": status,
                "resend_eligible": resend_eligible,
                "skip_eligible": skip_eligible,
            }
        assert False, "Failure"
        # else:
        #     return f"{response['GetAuthenticationQuestionsResponse']['GetAuthenticationQuestionsError']['Failure']['Message']}"


class CiBilVerifyAuthenticationAnswers(CiBilApi):
    PATH = "consumer/dtc/v4/VerifyAuthenticationAnswers"

    def __init__(
        self,
        pan: str = None,
        challenge_guid: int = None,
        answer: str = " ",
        resend_eligible: bool = False,
        skip_eligible: bool = False,
    ):
        self.answer = answer
        # self.cb = CiBilReport.objects.filter(pan=pan.upper(), pcc=self.pcc).last()
        # assert self.cb, "Cibil Application Fulfill Not Found"
        # self.cab = (
        #     self.cb.cibil_auth.filter(challenge_config_guid=challenge_guid, is_active=True)
        #     .exclude(status="Success")
        #     .last()
        # )
        self.cab = (
            CiBilReportAuthLogs.objects.filter(challenge_config_guid=challenge_guid, is_active=True)
            .exclude(status="Success")
            .last()
        )
        assert self.cab, "No Cibil Pending Auth Found"
        self.pcc = super().id_mask(refid=self.cab.cibil.pan)
        self.cb = self.cab.cibil

        self.data = {
            "VerifyAuthenticationAnswersRequest": {
                "ClientKey": self.pcc,
                "RequestKey": uuid.uuid4().__str__(),
                "PartnerCustomerId": self.pcc,
                "IVAnswer": {
                    "questionKey": self.cab.question_key,
                    "answerKey": self.cab.answer_choice,
                    "UserInputAnswer": answer,
                },
                "ChallengeConfigGUID": challenge_guid,
            }
        }
        if bool(distutils.util.strtobool(resend_eligible.__str__())):
            self.data["VerifyAuthenticationAnswersRequest"]["IVAnswer"].update({"reseneredOTP": True})
        if bool(distutils.util.strtobool(skip_eligible.__str__())):
            self.data["VerifyAuthenticationAnswersRequest"]["IVAnswer"].update({"skipQuestion": True})
        self.data["VerifyAuthenticationAnswersRequest"].update(self.AccountConfig)

    def __call__(self, *args, **kwargs):
        response = super().connect(path=self.PATH, method="POST", json=self.data)
        if response["VerifyAuthenticationAnswersResponse"]["ResponseStatus"] in ["Success"]:
            ivstatus = response["VerifyAuthenticationAnswersResponse"]["VerifyAuthenticationAnswersSuccess"][
                "IVStatus"
            ]
            if ivstatus in ["Pending", "InProgress"]:
                ivstatus = "Pending"
            self.cab.status = ivstatus
            self.cab.answer = self.answer
            # if ivstatus is Success then update in its means Reauthorization Approved
            if ivstatus in ["Success"]:
                self.cb.status = "Success"
                self.cb.save()
            self.cab.save()
            return ivstatus
        else:
            error = response["VerifyAuthenticationAnswersResponse"]["VerifyAuthenticationAnswersError"]
            self.cab.status = error["Failure"]["FailureEnum"]
            self.cab.save()
            assert False, f"{error['Failure']['Message']}"


class CiBilGetCustomerAssets(CiBilApi):
    PATH = "consumer/dtc/v4/GetCustomerAssets"

    def __init__(self, pan: str):
        self.pan = pan
        self.pcc = super().id_mask(refid=pan)
        self.cb = CiBilReport.objects.filter(pan=pan.upper(), pcc=self.pcc, status="Success").last()
        assert self.cb, "Cibi Report Pull Approval Not Granted Yet"

        self.data = {
            "GetCustomerAssetsRequest": {
                "ClientKey": self.pcc,
                "RequestKey": uuid.uuid4().__str__(),
                "PartnerCustomerId": self.pcc,
                "LegalCopyStatus": "Accept",
            }
        }
        self.data["GetCustomerAssetsRequest"].update(self.AccountConfig)

    def __call__(self, *args, **kwargs):
        from leads.models import Lead
        response = super().connect(path=self.PATH, method="POST", json=self.data)
        if response["GetCustomerAssetsResponse"]["ResponseStatus"] in ["Success"]:
            asset = response["GetCustomerAssetsResponse"]["GetCustomerAssetsSuccess"]["Asset"]
            json_report = response["GetCustomerAssetsResponse"]["GetCustomerAssetsSuccess"]
            report_timestamp = asset["CreationDate"]
            from dateutil import parser as dateparser

            report_timestamp = dateparser.parse(report_timestamp)
            score = asset["TrueLinkCreditReport"]["Borrower"]["CreditScore"]["riskScore"]
            score = int(score)
            if score in [1, "1"]:
                score = -1
            with transaction.atomic():
                try:
                    pass

                    control_number = asset["TrueLinkCreditReport"]["ReferenceKey"]
                    report = CiBilReport.objects.get(id=self.cb.id)
                    report.report_json = response
                    report.report_timestamp = report_timestamp
                    report.score = score
                    report.control_number = control_number
                    lead = Lead.objects.filter(id=report.lead_id).last()
                    if lead:
                        lead.credit_score = score
                        lead.save()
                    report.save()
                    try:
                        report.sync_to_s3()
                    except Exception as e:
                        logging.error(e, exc_info=True)
                    report.save()
                    report.update_lead_log()

                except Exception as e:
                    logging.error(e, exc_info=True)
            return response, score, report_timestamp, control_number
        else:
            assert (
                False
            ), f"{response['GetCustomerAssetsResponse']['GetCustomerAssetsError']['Failure']['FailureEnum']}"


class CiBilGetProductWebToken(CiBilApi):
    PATH = "consumer/dtc/v4/GetProductWebToken"
    PATH_REPORT = "CreditView/webtokenasset.page?enterprise={SiteName}&pcc={pcc}&webtoken={web_token}"

    def __init__(self, pan: str):
        self.pan = pan
        self.pcc = super().id_mask(refid=pan)
        self.cb = CiBilReport.objects.filter(pan=pan.upper(), pcc=self.pcc, status="Success").last()
        assert self.cb, "Cibi Report Pull Approval Not Granted Yet"

        self.data = {
            "GetProductWebTokenRequest": {
                "ClientKey": self.pcc,
                "RequestKey": uuid.uuid4().__str__(),
                "PartnerCustomerId": self.pcc,
            }
        }
        self.data["GetProductWebTokenRequest"].update(self.AccountConfig)

    def report_url(self, web_token: str):
        return f"{self.BASE_URL_REPORT}{self.PATH_REPORT.format(SiteName=self.SiteName, pcc=self.pcc, web_token=web_token)}"

    def __call__(self, *args, **kwargs):
        response = super().connect(path=self.PATH, method="POST", json=self.data)
        if response["GetProductWebTokenResponse"]["ResponseStatus"] == "Success":
            return self.report_url(
                web_token=response["GetProductWebTokenResponse"]["GetProductWebTokenSuccess"]["WebToken"]
            )
        assert False, f"{response['GetProductWebTokenResponse']['GetProductWebTokenError']['Failure']['Message']}"
