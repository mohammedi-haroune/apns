from enum import Enum
from uuid import uuid4

PRIORITY_NORMAL = "5"
PRIORITY_HIGH = "10"


class PushType(Enum):
    ALERT = "alert"
    BACKGROUND = "background"
    VOIP = "voip"
    COMPLICATION = "complication"
    FILEPROVIDER = "fileprovider"
    MDM = "mdm"


class NotificationRequest:
    __slots__ = (
        "device_token",
        "message",
        "notification_id",
        "time_to_live",
        "priority",
        "collapse_key",
        "push_type",
    )

    def __init__(
        self,
        device_token,
        message,
        notification_id=None,
        time_to_live=None,
        priority=None,
        collapse_key=None,
        push_type=None,
    ):
        self.device_token = device_token
        self.message = message
        self.notification_id = notification_id or str(uuid4())
        self.time_to_live = time_to_live
        self.priority = priority
        self.collapse_key = collapse_key
        self.push_type = push_type


class NotificationResult:
    __slots__ = ("notification_id", "status", "description")

    def __init__(self, notification_id, status, description=None):
        self.notification_id = notification_id
        self.status = status
        self.description = description

    @property
    def is_successful(self):
        return self.status == APNS_RESPONSE_CODE.SUCCESS


class APNS_RESPONSE_CODE:
    SUCCESS = "200"
    BAD_REQUEST = "400"
    FORBIDDEN = "403"
    METHOD_NOT_ALLOWED = "405"
    GONE = "410"
    PAYLOAD_TOO_LARGE = "413"
    TOO_MANY_REQUESTS = "429"
    INTERNAL_SERVER_ERROR = "500"
    SERVICE_UNAVAILABLE = "503"
