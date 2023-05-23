from django.apps import AppConfig
from django.conf import settings

class AccountConfig(AppConfig):
    name = 'account'
    verbose_name = 'Admin Fyxt'

    def ready(self):
        import account.signals
        # if settings.LISTEN_MQ:
        #     from fyxt.mq.receivers import Company
        #     receive = Company()
        #     receive.daemon = True
        #     receive.start()
