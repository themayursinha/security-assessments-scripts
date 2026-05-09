#/bin/python

import socketserver
import socket

SERVER_ADDRESS = ("0.0.0.0", 8888)

class EchoHandler(socketserver.BaseRequestHandler):

  def handle(self):

    print("Received a connection from: ", self.client_address)
    data = b"start"
    while len(data):
      data = self.request.recv(1024)
      self.request.sendall(data)
      print("%s said: "%str(self.client_address), data.decode(errors="replace"))

    print("%s disconnected"%str(self.client_address))


if __name__ == '__main__':

  print("Listening on %s"%str(SERVER_ADDRESS))
  server = socketserver.TCPServer(SERVER_ADDRESS, EchoHandler)
  server.serve_forever()
