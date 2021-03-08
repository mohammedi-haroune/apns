import json
import ssl
import time
from typing import Callable, NoReturn, Optional
from time import sleep

import jwt
import OpenSSL
from hyper import HTTP20Connection
from aioapns.logging import logger


class AuthorizationHeaderProvider:
    def get_header(self):
        raise NotImplementedError


class JWTAuthorizationHeaderProvider(AuthorizationHeaderProvider):

    TOKEN_TTL = 30 * 60

    def __init__(self, key, key_id, team_id):
        self.key = key
        self.key_id = key_id
        self.team_id = team_id

        self.__issued_at = None
        self.__header = None

    def get_header(self):
        now = time.time()
        if not self.__header or self.__issued_at < now - self.TOKEN_TTL:
            self.__issued_at = int(now)
            token = jwt.encode(
                payload={"iss": self.team_id, "iat": self.__issued_at},
                key=self.key,
                algorithm="ES256",
                headers={"kid": self.key_id},
            )
            self.__header = f"bearer {token}"
        return self.__header


class APNsBaseClientProtocol:
    APNS_SERVER = "api.push.apple.com"
    APNS_PORT = None
    SECURE = True

    def __init__(
        self,
        apns_topic: str,
        auth_provider: Optional[AuthorizationHeaderProvider] = None,
        **hyper_kwargs,
    ):
        self.apns_topic = apns_topic
        self.auth_provider = auth_provider

        self.requests = {}
        self.request_streams = {}
        self.request_statuses = {}

        self.hyper_kwargs = hyper_kwargs

    def send_notification(self, request):
        headers = {
            "apns-id": request.notification_id,
            "apns-topic": self.apns_topic,
        }
        if request.time_to_live is not None:
            expiration = int(time.time()) + request.time_to_live
            headers["apns-expiration"] = str(expiration)
        if request.priority is not None:
            headers["apns-priority"] = str(request.priority)
        if request.collapse_key is not None:
            headers["apns-collapse-id"] = request.collapse_key
        if request.push_type is not None:
            headers["apns-push-type"] = request.push_type.value
        if self.auth_provider:
            headers["authorization"] = self.auth_provider.get_header()

        data = json.dumps(request.message, ensure_ascii=False).encode()

        request_kwargs = {
            'method': 'POST',
            'url': f'/3/device/{request.device_token}',
            'body': data,
            'headers': headers
        }
        logger.debug(f'Sending request {request_kwargs}')

        self.conn = HTTP20Connection(
            host=self.APNS_SERVER,
            port=self.APNS_PORT,
            scheme='https',
            secure=self.SECURE,
            **self.hyper_kwargs,
        )

        stream_id = self.conn.request(**request_kwargs)

        response = self.conn.get_response(stream_id=stream_id)

        return response

class APNsTLSClientProtocol(APNsBaseClientProtocol):
    APNS_PORT = 443

class APNsProductionClientProtocol(APNsTLSClientProtocol):
    APNS_SERVER = "api.push.apple.com"


class APNsDevelopmentClientProtocol(APNsTLSClientProtocol):
    APNS_SERVER = "api.development.push.apple.com"


class APNsBaseConnectionPool:
    def __init__(
        self,
        topic: Optional[str] = None,
        max_connections: int = 10,
        max_connection_attempts: Optional[int] = None,
        use_sandbox: bool = False,
    ):

        self.apns_topic = topic
        self.max_connections = max_connections
        if use_sandbox:
            self.protocol_class = APNsDevelopmentClientProtocol
        else:
            self.protocol_class = APNsProductionClientProtocol

        self.connections = []
        self.max_connection_attempts = max_connection_attempts

    def create_connection(self):
        raise NotImplementedError

    def send_notification(self, request):
        connection = self.create_connection()
        response = connection.send_notification(request)
        return response

class APNsCertConnectionPool(APNsBaseConnectionPool):
    def __init__(
        self,
        cert_file: str,
        topic: Optional[str] = None,
        max_connections: int = 10,
        max_connection_attempts: Optional[int] = None,
        use_sandbox: bool = False,
        no_cert_validation: bool = False,
        ssl_context: Optional[ssl.SSLContext] = None,
    ):

        super(APNsCertConnectionPool, self).__init__(
            topic=topic,
            max_connections=max_connections,
            max_connection_attempts=max_connection_attempts,
            use_sandbox=use_sandbox,
        )

        self.cert_file = cert_file
        self.ssl_context = ssl_context or ssl.create_default_context()
        if no_cert_validation:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        self.ssl_context.load_cert_chain(cert_file)

        if not self.apns_topic:
            with open(self.cert_file, "rb") as f:
                body = f.read()
                cert = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_PEM, body
                )
                self.apns_topic = cert.get_subject().UID

    def create_connection(self):
        protocol = self.protocol_class(
            self.apns_topic,
            # ssl_context=self.ssl_context,
        )
        return protocol


class APNsKeyConnectionPool(APNsBaseConnectionPool):
    def __init__(
        self,
        key_file: str,
        key_id: str,
        team_id: str,
        topic: str,
        max_connections: int = 10,
        max_connection_attempts: Optional[int] = None,
        use_sandbox: bool = False,
        ssl_context: Optional[ssl.SSLContext] = None,
    ):

        super(APNsKeyConnectionPool, self).__init__(
            topic=topic,
            max_connections=max_connections,
            max_connection_attempts=max_connection_attempts,
            use_sandbox=use_sandbox,
        )

        self.ssl_context = ssl_context or ssl.create_default_context()

        self.key_id = key_id
        self.team_id = team_id

        with open(key_file) as f:
            self.key = f.read()

    def create_connection(self):
        auth_provider = JWTAuthorizationHeaderProvider(
            key=self.key, key_id=self.key_id, team_id=self.team_id
        )
        # TODO: why passing ssl_context as hyper_kwargs results in 
        # Traceback (most recent call last):
        #   File "client.py", line 56, in <module>
        #     main()
        #   File "client.py", line 52, in main
        #     response = send_request()
        #   File "client.py", line 49, in send_request
        #     return apns.send_notification(request)
        #   File "/home/mohammedi/open-source/aioapns/venv/lib/python3.8/site-packages/aioapns/client.py", line 53, in send_notification
        #     return self.pool.send_notification(request)
        #   File "/home/mohammedi/open-source/aioapns/venv/lib/python3.8/site-packages/aioapns/connection.py", line 140, in send_notification
        #     response = connection.send_notification(request)
        #   File "/home/mohammedi/open-source/aioapns/venv/lib/python3.8/site-packages/aioapns/connection.py", line 99, in send_notification
        #     stream_id = self.conn.request(**request_kwargs)
        #   File "/home/mohammedi/open-source/aioapns/venv/lib/python3.8/site-packages/hyper/http20/connection.py", line 281, in request
        #     self.endheaders(message_body=body, final=True, stream_id=stream_id)
        #   File "/home/mohammedi/open-source/aioapns/venv/lib/python3.8/site-packages/hyper/http20/connection.py", line 544, in endheaders
        #     self.connect()
        #   File "/home/mohammedi/open-source/aioapns/venv/lib/python3.8/site-packages/hyper/http20/connection.py", line 373, in connect
        #     assert proto in H2_NPN_PROTOCOLS or proto == H2C_PROTOCOL
        # AssertionError
        protocol = self.protocol_class(
            apns_topic=self.apns_topic,
            auth_provider=auth_provider,
            # ssl_context=self.ssl_context,
        )
        return protocol
