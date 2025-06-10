from mitmproxy import http
import logging

logging.basicConfig(filename="traffic_log.txt",
                    level=logging.INFO,
                    format="%(asctime)s - %(message)s",
                    force=True
                    )

class Logger:
    def request(self, flow: http.HTTPFlow):
        logging.info(f"[Request] {flow.request.method} {flow.request.pretty_url}")
        for handler in logging.getLogger().handlers:
            handler.flush()

    def response(self, flow: http.HTTPFlow):
        logging.info(f"[Response] {flow.response.status_code} - {flow.request.pretty_url}")
        for handler in logging.getLogger().handlers:
            handler.flush()

addons = [Logger()]
