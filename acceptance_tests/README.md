# DNS Server Acceptance Tests

This directory contains independent acceptance tests for validating the DNS server's compliance with RFC 1035 using real DNS protocol messages.

## Overview

These tests use the `dnspython` library to create actual DNS queries and send them to your running DNS server. The tests verify that your server responds correctly according to the DNS protocol specifications.

## Requirements

- Python 3.7+
- The packages listed in `requirements.txt`

## Setup

1. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Make sure your DNS server is properly built:
   ```bash
   mkdir -p ../build
   cd ../build
   cmake ..
   make
   ```

## Running the Tests

To run all tests:
```bash
pytest
```

To run tests with detailed output:
```bash
pytest -v
```

To generate an HTML report:
```bash
pytest --html=report.html
```

## Test Suite Contents

The test suite validates:

1. **A Record Resolution** - Basic IPv4 address lookups
2. **MX Record Resolution** - Mail exchanger record handling
3. **CNAME Resolution** - Canonical name record handling and following
4. **NS Record Resolution** - Nameserver record handling
5. **TXT Record Resolution** - Text record handling
6. **PTR Record Resolution** - Reverse DNS lookups
7. **SOA Record Resolution** - Start of Authority record handling
8. **Non-existent Domain Handling** - Proper NXDOMAIN responses
9. **Case Insensitivity** - Handling mixed-case domain names (RFC 1035 Section 2.3.3)
10. **Truncated Responses** - Handling large responses that exceed UDP limits

## Modifying the Tests

- The server IP and port can be configured at the top of the `test_dns_server.py` file.
- Additional tests can be added by creating new test methods in the `TestDNSServer` class.

## Troubleshooting

- If the tests fail to connect to your DNS server, make sure your server is running and listening on the correct port.
- Ensure your server is properly handling UDP and possibly TCP connections.
- Check that your server is properly binding to the address specified in the test configuration.
