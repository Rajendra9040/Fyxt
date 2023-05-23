import threading
import json
import pika
from django.conf import settings
from fyxt.utils.fyxt_cc import create_company
class MetaClass(type):
    __instances = {}
    def __call__(cls, *args, **kwargs):
        """ Singleton Design Pattern"""
        if cls not in cls.__instances:
            cls.__instances[cls] = super(MetaClass, cls).__call__(*args, **kwargs)
        return cls.__instances[cls]
class Receiver(threading.Thread, metaclass=MetaClass):
    def connect(self, exchange='cc', routing_key='company.create', queue='company_create'):
        self.routing_key = routing_key
        self.exchange = exchange
        self.queue = queue
        self._connection = pika.BlockingConnection(pika.URLParameters(settings.MQ_HOST))
        self._channel = self._connection.channel()
        self._channel.queue_declare(self.queue)
        self._channel.queue_bind(exchange=self.exchange, routing_key=self.routing_key, queue=self.queue)
    @staticmethod
    def callback(ch, method, properties, body):
        payload = json.loads(body)
        # Here the create method will be called.
        print(f'[x] Received {payload}')
        create_company(payload)
        ch.basic_ack(delivery_tag=method.delivery_tag)
    def run(self):
        """
        :return:
        """
        self.connect()
        self._channel.basic_consume(on_message_callback=self.callback, queue=self.queue)
        print('[*] Waiting for message...')
        self._channel.start_consuming()
