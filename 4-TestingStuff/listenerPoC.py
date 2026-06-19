import socket
import traceback

from io import BytesIO

from http.server import BaseHTTPRequestHandler


class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("",12345))
    s.listen(5)

    while True:
        try:
            c, addr = s.accept()
            print(f"Got connection from: {addr}")
            # c.send(b"'220 Welcome!\r\n'")
            for _ in range(10):
                r = c.recv(10485760)
                print(r)
                c.send(r)
            # parsed = HTTPRequest(r)
            # if parsed.error_code is None:
            #     print(parsed.headers)
            #     print(parsed.request_version)
            #     print(parsed.rfile.readline().decode())

            #     response = b"HTTP/1.0 200 OK\nServer: TotalLegitServer/0.3 Python/3000\nContent-type: text/html\n\n<html><head><title>WoW</title></head>"
            # else:
            #     print(r)
            #     response = b"Welcome"
            # c.send(response)
            c.send(r)
            c.close()
        except KeyboardInterrupt:
            try:
                c.close()
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            s.close()
            break
        except Exception:
            c.close()
            print(traceback.format_exc())


if __name__ == "__main__":
    main()