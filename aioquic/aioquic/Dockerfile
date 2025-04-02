FROM python:3.8-slim

WORKDIR /app

COPY . /app

RUN pip install aioquic==0.9.25
RUN pip install wsproto
RUN pip install starlette
RUN pip install aiohttp

EXPOSE 4433

CMD ["python3", "http3_server.py", "--certificate=ssl_cert.pem", "--private-key=ssl_key.pem", "proxy:app", "-v"]
#RUN python3 examples/http3_server.py --certificate ssl_cert.pem --private-key ssl_key.pem proxy:app -v
