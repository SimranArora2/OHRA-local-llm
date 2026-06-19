"""
A PoC that has been adapted from
https://docs.python.org/3.8/library/selectors.html#module-selectors
to experiment with listening on multiple ports
"""
import time
import selectors
import socket

sel = selectors.DefaultSelector()
connections = {}  # Dictionary to track last activity time for each connection
TIMEOUT = 10  # Timeout in seconds

def accept(sock, mask):
    conn, addr = sock.accept()  # Should be ready
    print('accepted', conn, 'from', addr)
    conn.setblocking(False)
    sel.register(conn, selectors.EVENT_READ, read)
    connections[conn] = time.time()

def read(conn, mask):
    now = time.time()
    data = conn.recv(1000)  # Should be ready
    if data:
        print('echoing', repr(data), 'to', conn)
        print("Remote info:")
        print(conn.getpeername())
        print("Local info:")
        print(conn.getsockname())
        conn.send(data)  # Hope it won't block
        connections[conn] = now # update last activity
    else:
        print('closing', conn)
        sel.unregister(conn)
        del connections[conn]
        conn.close()

def check_timeouts():
    now = time.time()
    # cannot use .items() since this
    # will lead to runtime errors as
    # this for loop modifies the dictionary!
    for conn in list(connections.keys()):
        if now - connections[conn] > TIMEOUT:
            print('closing due to inactivity', conn)
            sel.unregister(conn)
            del connections[conn]  # Remove from tracking
            conn.close()

for port in list(range(1200,1205)):
    socket.setdefaulttimeout(10)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", port))
    sock.listen(5)
    sock.setblocking(False)
    sel.register(sock, selectors.EVENT_READ, accept)

try:
    while True:
        events = sel.select(timeout=5.0)
        for key, mask in events:
            callback = key.data
            callback(key.fileobj, mask)
        check_timeouts()
except KeyboardInterrupt:
    print("Goodbye")
finally:
    # Clean up remaining connections
    for conn in connections:
        sel.unregister(conn)
        conn.close()
