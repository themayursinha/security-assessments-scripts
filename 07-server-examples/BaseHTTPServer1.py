import time
import http.server


HOST = 'localhost' # set you host
PORT = 31337 # set your port


class Server(http.server.BaseHTTPRequestHandler):

    def do_HEAD(s):
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()

    def do_GET(s):
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
        s.wfile.write(b"<html><head><title>Titles.</title></head>")
        s.wfile.write(b"<body><p>and stuff.</p>")
        s.wfile.write(b"</body></html>")

if __name__ == '__main__':
    server_class = http.server.HTTPServer
    httpd = server_class((HOST, PORT), Server)
    print(time.asctime(), "Server On - %s:%s" % (HOST, PORT))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print(time.asctime(), "Server Off - %s:%s" % (HOST, PORT))
