from functools import wraps

from flask import request
from datetime import datetime

from indralab_auth_tools.src.models import QueryLog

SERVICE_NAME = None
CURRENT_LOG = None


class QueryLogRecorder:
    def __init__(self, service_name):
        self.service_name = service_name
        self.start_time = None
        self.end_time = None
        self.result_status = None
        self.user_id = None
        self.user_ip = request.environ['REMOTE_ADDR']
        self.user_agent = request.environ['HTTP_USER_AGENT']
        self.url = request.url
        self.annotations = {}

    def start(self):
        """Start this log, marking the start time."""
        if self.start_time is not None:
            return
        self.start_time = datetime.utcnow()

    def set_user(self, user):
        self.user_id = user.id

    def end(self, status):
        """Eng this log, marking the end time."""
        if self.end_time is not None:
            return
        self.end_time = datetime.utcnow()
        self.result_status = status

    def save(self):
        """Save this record to the user database."""
        entry = QueryLog(start_date=self.start_time, end_date=self.end_time,
                         url=self.url, user_ip=self.user_ip,
                         user_agent=self.user_agent, user_id=self.user_id,
                         annotations=self.annotations,
                         result_status=self.result_status,
                         service_name=self.service_name)
        entry.save()
        return

    def json(self):
        """Get JSON form of the log."""
        time_fmt = "%Y-%d-%m %H:%M:%S"
        return {'start_time': self.start_time.strftime(time_fmt),
                'end_time': self.end_time.strftime(time_fmt),
                'user_ip': self.user_ip, 'user_agent': self.user_agent,
                'url': self.url, 'annotations': self.annotations}

    def add_notes(self, **kwargs):
        """Add notes to the logged query."""
        self.annotations.update(kwargs)


def set_log_service_name(service_name):
    global SERVICE_NAME
    SERVICE_NAME = service_name
    return


def is_log_running():
    return CURRENT_LOG is not None


def start_log(service_name):
    global CURRENT_LOG
    assert CURRENT_LOG is None
    CURRENT_LOG = QueryLogRecorder(service_name)
    CURRENT_LOG.start()
    return


def set_user_in_log(user):
    assert isinstance(CURRENT_LOG, QueryLogRecorder)
    CURRENT_LOG.set_user(user)
    return


def end_log(status):
    global CURRENT_LOG
    log_json = {}
    try:
        assert isinstance(CURRENT_LOG, QueryLogRecorder)
        try:
            CURRENT_LOG.end(status)
            CURRENT_LOG.save()
            log_json = CURRENT_LOG.json()
        except Exception:
            pass
    finally:
        CURRENT_LOG = None
    return log_json


def user_log_endpoint(func):

    @wraps(func)
    def run_logged(*args, **kwargs):
        start_log(SERVICE_NAME)
        try:
            resp = func(*args, **kwargs)
            if isinstance(resp, str):
                status = 200
            else:
                status = resp.status
        except Exception as e:
            status = 500
        end_log(status)
        return resp

    return run_logged


def note_in_log(**arguments):
    """Log a usage event of an indralab service.

    DO *NOT* log user login data (this would store passwords in plain text).
    """
    assert isinstance(CURRENT_LOG, QueryLogRecorder)
    CURRENT_LOG.add_notes(**arguments)
    return
