#!/usr/bin/env python3

from http.server import HTTPServer, BaseHTTPRequestHandler
import time
import json

class DelayedResponseHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Read the request body
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        # Print the request for debugging
        print(f"Received lookup request: {post_data}")
        
        # Deliberately delay the response by 3 seconds
        print("Delaying response for 3 seconds...")
        time.sleep(3)
        
        # Send a response indicating the file is allowed
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response = {
            "verdict": "log",  # Changed from "block" to "log"
            "file_name": "Test File",
            "confidence": 100
        }
        
        self.wfile.write(json.dumps(response).encode())
        print("Sent response: file is allowed (log verdict)")

def run_server(port=8080):
    server_address = ('', port)
    httpd = HTTPServer(server_address, DelayedResponseHandler)
    print(f"Starting mock lookup service on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()