import asyncio
from urllib.parse import urlparse

tests = 0


async def perform_tests(client, url, http_request):
    await test_header_values(client, url, http_request)
    await test_header_names(client, url, http_request)
    await test_forbidden_and_conflicting_headers(client, url, http_request)
    await test_removing_headers(client, url, http_request)
    return tests


### Used for logging
def log_test(test_type, detailed_description, response_status_code=None, flag=None, timeout=False, error_message=None):
    if timeout:
        log_txt = "[TEST " + str(tests) + "] " + test_type + " - " + detailed_description + " - timeout - errormsg: " + error_message
    else:
        log_txt = "[TEST " + str(tests) + "] " + test_type + " - " + detailed_description + " - response: " + response_status_code.decode() + " - flag: " + str(flag)
    
    print(log_txt)

    f = open("test.log", "a")
    f.write(log_txt + "\n")
    f.close()

### Checks if a string, resp. a header name or header value, was forwarded to the backend.
### The backends response contains the initial request.
def check_response(res, test):
    if res[0].headers[0][1] != b"200":
        return False
    else:
        return test in res[1].data


def get_headers(url, post_request=False, add_header=None, remove_header=None):
    parsed_url = urlparse(url)
    full_path = parsed_url.path
    headers = [
                (b":method", b"GET" if not post_request else b"POST"),
                (b":scheme", b"https"),
                (b":authority", parsed_url.netloc.encode()),
                (b":path", full_path.encode()),
                (b"user-agent", ("smuggling-test-no-" + str(tests)).encode())
            ]
    
    if remove_header is not None:
        for i, header in enumerate(headers):
            if header[0] == remove_header:
                del headers[i]
                break

    if add_header is not None:
        headers.append(add_header)

    return headers


async def test_header_values(client, url, http_request):
    global tests
    forbidden = [chr(0x0), chr(0x0a), chr(0x0d), chr(0x09), chr(0x20)]
    for char in forbidden:
        tests+=1
        loads = [char.encode()+b"smuggling",
                 b"smuggling"+char.encode(),
                 b"smugg"+char.encode()+b"ling"]
        load_types = ["prefix ", "postfix", "infix  "]

        for i, load in enumerate(loads):
            
            headers = get_headers(url, add_header=(b"smuggling", load))

            try:
                res = await asyncio.wait_for(http_request(
                    client=client,
                    urls=[url],
                    headers=headers,
                ), timeout= 2)
                header_reached_backend = check_response(res, load)
                log_test("header value", f"{ord(char):#04x}" + " as " + load_types[i], res[0].headers[0][1], header_reached_backend)
            except Exception as e:
                log_test("header value", f"{ord(char):#04x}" + " as " + load_types[i], timeout=True, error_message=str(e))
                pass


async def test_header_names(client, url, http_request):
    global tests
    forbidden = []
    for i in range(0x0, 0x21):
        forbidden.append(chr(i))
    for i in range(0x41,0x5b):
        forbidden.append(chr(i))
    for i in range(0x7f,0x100):
        forbidden.append(chr(i))
    for i in range(len(forbidden)):
        tests+=1

        headers = get_headers(url, add_header=(b"malicious"+forbidden[i].encode()+b"header",b"test"))

        try:
            res = await asyncio.wait_for(http_request(client=client,
                                                      urls=[url],
                                                      headers=headers),
                                                    timeout=2)
            header_reached_backend = check_response(res, b"malicious"+forbidden[i].encode()+b"header")
            log_test("header name", f"{ord(forbidden[i]):#04x}", res[0].headers[0][1], header_reached_backend)
        except Exception as e:
            log_test("header name", f"{ord(forbidden[i]):#04x}", timeout=True, error_message=str(e))


async def test_forbidden_and_conflicting_headers(client, url, http_request):
    global tests

              # Title for loggin #                   # Added headers #                 # Removed headers #  # Data #
    loads = [["transfer encoding",                  (b"transfer-encoding",b"chunked"), None,                "0\r\nGET /test HTTP/1.1\r\n\r\n"], 
             ["content length",                     (b"content-length",b"2"),          None,                "test"],
             ["pseudo-header after regular header", (b":path",b"/"),                   b":path",            None],
             ["conflicting host",                   (b"host",b"test:1234"),            None,                None],
             ["invalid pseudo header",              (b":random",b"test"),              None,                None],
             ["dublicate pseudo header",            (b":authority",b"evil.com:443"),   None,                None]
            ]
    
    for load in loads:
        tests+=1
        headers = get_headers(url, add_header=load[1], remove_header=load[2], post_request=(load[3] is not None))
        try:
            res = await asyncio.wait_for(http_request(client=client, urls=[url], headers=headers, data=load[3]), timeout=2)
            log_test("forbidden/conflicting header", load[0], res[0].headers[0][1])
            # Print out server-response if client recieved 200 OK
            if res[0].headers[0][1] == b"200":
                print("\nSERVER-RESPONSE:")
                print(res)
                print("")
        except Exception as e:
            log_test("forbidden/conflicting header", load[0], timeout=True, error_message=str(e))
            pass


async def test_removing_headers(client, url, http_request):
    global tests
    remove_headers = [b":method",
                      b":scheme",
                      b":authority",
                      b":path"]
    for header in remove_headers:
        tests+=1
        headers = get_headers(url, remove_header=header)
        try:
            res = await asyncio.wait_for(http_request(client=client, urls=[url], headers=headers), timeout=5)
            log_test("removing pseudo header", header.decode(), res[0].headers[0][1])
        except Exception as e:
            log_test("removing pseudo header", header.decode(), timeout=True, error_message=str(e))
            pass

