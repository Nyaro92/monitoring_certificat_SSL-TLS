import socket
import ssl

def get_certificate(hostname, port=443):
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, int(port)), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secured_sock:
                return secured_sock.getpeercert(binary_form=True)
    except Exception:
        return None