# HTTP3 Proxy Tester

### The repository contains both the tool and the proxy configurations

## How to run the proxies
### Each directory contains a proxy setup, except for Aioquic every other proxy is dockerized, so just go on the directory and run
``` docker-compose up --build -d ```

### For Aioquic you need to clone the repository (https://github.com/aiortc/aioquic.git). Then put the /aioquic/aioquic/proxy.py file (of this repository) inside /examples/ (of the Aioquic repository). Then you can run the following command to start the server
 ``` python3 examples/http3_server.py --certificate tests/ssl_cert.pem --private-key tests/ssl_key.pem --port 443 -v proxy:app```

## How to run the tool

### After the proxy is correctly running you can type the following command to run the tests
``` python3 smuggling.py https://localhost:443 ```


## A huge thank you to the users that provide fully configured dockerized instances of proxies
### https://github.com/macbre/docker-nginx-http3
### https://github.com/dhmosfunk/HTTP3ONSTEROIDS
### https://github.com/josue/docker-caddy-reverse-proxy
### https://github.com/PutziSan/http3-docker-compose-traefik-test