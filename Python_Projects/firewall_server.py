from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

# Define blocked parameters and headers related to Spring4Shell exploit
BLOCKED_HEADERS = {"suffix", "c1", "c2", "DNT"}
BLOCKED_PAYLOADS = {"class.module.classLoader.resources.context.parent.pipeline.first"}

class FirewallServer(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        parsed_data = urllib.parse.parse_qs(post_data)
        
        # Check for malicious headers
        for header in BLOCKED_HEADERS:
            if header in self.headers:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Blocked: Malicious Header Detected")
                return
        
        # Check for malicious payloads
        for key in parsed_data:
            if any(blocked in key for blocked in BLOCKED_PAYLOADS):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Blocked: Malicious Payload Detected")
                return
        
        # Allow legitimate requests
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Request Allowed")

if __name__ == "__main__":
    server_address = ('', 8080)  # Listen on port 8080
    httpd = HTTPServer(server_address, FirewallServer)
    print("Firewall HTTP Server running on port 8080...")
    httpd.serve_forever()
