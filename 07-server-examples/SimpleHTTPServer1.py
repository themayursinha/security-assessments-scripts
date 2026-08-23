#/bin/python

import socketserver
import http.server

PORT = 8888

class HTTPRequestHandler (http.server.SimpleHTTPRequestHandler):

  def do_GET(self):
    if self.path == '/test' :
      self.send_response(200)
      self.send_header("Content-type", "text/plain")
      self.end_headers()
      self.wfile.write(b'You have found the test page!\n')
      self.wfile.write(str(self.headers).encode())
    else:
      http.server.SimpleHTTPRequestHandler.do_GET(self)


if __name__ == '__main__':
  print("Starting server on port %d"%PORT)
  httpServer = socketserver.TCPServer(("",PORT), HTTPRequestHandler)
  httpServer.serve_forever()
