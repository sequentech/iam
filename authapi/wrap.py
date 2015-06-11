from time import time
from logging import getLogger


class LoggingMiddleware(object):
    def __init__(self):
        # arguably poor taste to use django's logger
        self.logger = getLogger('django.request')
        self.timer = 0

    def process_request(self, request):
        self.timer = time()
        return None

    def process_response(self, request, response):
        if response.status_code == 200:
            return response

        self.logger.info(
            '[%s] %s %s (%.1fs)\n\trequest=%s\n\tresponse=%s',
            response.status_code,
            request.method,
            request.get_full_path(),
            time() - self.timer,
            request.body,
            response.content
        )
        return response