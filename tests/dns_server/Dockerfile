FROM python:3.12-slim

WORKDIR /app
COPY tests/dns_server/dns_test_server.py /app/dns_test_server.py

EXPOSE 53/tcp 53/udp 8053/tcp
CMD ["python3", "/app/dns_test_server.py"]
