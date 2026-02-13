import json
import time
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

class MockLimeSurveyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        try:
            data = json.loads(post_data)
        except:
            self.send_response(400)
            self.end_headers()
            return

        method = data.get("method")
        params = data.get("params", [])

        response = {"id": data.get("id", 1), "result": None, "error": None}

        if method == "get_session_key":
            response["result"] = "MOCK_SESSION_12345"

        elif method == "mail_registered_participants":
            # params: [session_key, survey_id, [override_condition]]
            if len(params) < 3 or params[0] != "MOCK_SESSION_12345":
                response["error"] = "Invalid session"
            else:
                condition = params[2][0] if isinstance(params[2], list) else params[2]

                # Simulate Time-based SQLi
                if "SLEEP" in str(condition):
                    delay = 5
                    match = re.search(r"SLEEP\((\d+)\)", str(condition))
                    if match:
                        delay = int(match.group(1))
                    else:
                        # Handle SLEEP(2-(IF(43=43,0,2)))
                        match_if = re.search(r"IF\((\d+)=(\d+),0,2\)", str(condition))
                        if match_if:
                            if match_if.group(1) == match_if.group(2):
                                delay = 2
                            else:
                                delay = 0
                        elif "SLEEP(2)" in str(condition):
                            delay = 2

                    if delay > 0:
                        time.sleep(delay)
                    response["result"] = "Success (Delayed %ds)" % delay

                # Simulate Error-based SQLi
                elif "EXTRACTVALUE" in str(condition):
                    response["error"] = "SQLSTATE[42000]: Syntax error: XPATH syntax error: '~XPATH_ERROR~'"

                # Simulate Boolean-based SQLi
                elif "1=1" in str(condition):
                    response["result"] = ["participant1", "participant2"]
                elif "1=2" in str(condition):
                    response["result"] = []
                else:
                    response["result"] = "Status: OK"

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

def run(port=8080):
    server_address = ('', port)
    httpd = ThreadedHTTPServer(server_address, MockLimeSurveyHandler)
    print(f"Starting mock server on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
