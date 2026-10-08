import http.server
import socketserver
import sys

PORT = 54321

class EchoHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Hello from host local database service!\n")

    def log_message(self, format, *args):
        # suppress noisy access logs for demo clarity
        pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    with socketserver.TCPServer(("127.0.0.1", port), EchoHandler) as httpd:
        print(f"Mock service listening on 127.0.0.1:{port}", flush=True)
        httpd.serve_forever()
