#  Copyright 2026 SURF.
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
from flask.testing import FlaskClient

# From: https://raw.githubusercontent.com/pyca/cryptography/refs/heads/main/docs/x509/reference.rst
trust_anchor_example_cert_pem_bytes = b"""
-----BEGIN CERTIFICATE-----
MIIDfDCCAmSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf
MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg
QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowQDELMAkGA1UE
BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExEDAOBgNVBAMT
B0dvb2QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQWJpHYo37
Xfb7oJSPe+WvfTlzIG21WQ7MyMbGtK/m8mejCzR6c+f/pJhEH/OcDSMsXq8h5kXa
BGqWK+vSwD/Pzp5OYGptXmGPcthDtAwlrafkGOS4GqIJ8+k9XGKs+vQUXJKsOk47
RuzD6PZupq4s16xaLVqYbUC26UcY08GpnoLNHJZS/EmXw1ZZ3d4YZjNlpIpWFNHn
UGmdiGKXUPX/9H0fVjIAaQwjnGAbpgyCumWgzIwPpX+ElFOUr3z7BoVnFKhIXze+
VmQGSWxZxvWDUN90Ul0tLEpLgk3OVxUB4VUGuf15OJOpgo1xibINPmWt14Vda2N9
yrNKloJGZNqLAgMBAAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZ
XahmMB0GA1UdDgQWBBRYAYQkG7wrUpRKPaUQchRR9a86yTAOBgNVHQ8BAf8EBAMC
AQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJ
KoZIhvcNAQELBQADggEBADWHlxbmdTXNwBL/llwhQqwnazK7CC2WsXBBqgNPWj7m
tvQ+aLG8/50Qc2Sun7o2VnwF9D18UUe8Gj3uPUYH+oSI1vDdyKcjmMbKRU4rk0eo
3UHNDXwqIVc9CQS9smyV+x1HCwL4TTrq+LXLKx/qVij0Yqk+UJfAtrg2jnYKXsCu
FMBQQnWCGrwa1g1TphRp/RmYHnMynYFmZrXtzFz+U9XEA7C+gPq4kqDI/iVfIT1s
6lBtdB50lrDVwl2oYfAvW/6sC2se2QleZidUmrziVNP4oEeXINokU6T6p//HM1FG
QYw2jOvpKcKtWCSAnegEbgsGYzATKjmPJPJ0npHFqzM=
-----END CERTIFICATE-----
""".strip()

# HTTP/Traefik cannot carry newlines and compresses
trust_anchor_example_cert_pem_str = trust_anchor_example_cert_pem_bytes.decode("iso-8859-1")
trust_anchor_example_cert_pem_str = trust_anchor_example_cert_pem_str.replace("-----BEGIN CERTIFICATE-----", "")
trust_anchor_example_cert_pem_str = trust_anchor_example_cert_pem_str.replace("-----END CERTIFICATE-----", "")
trust_anchor_example_cert_pem_str = trust_anchor_example_cert_pem_str.replace("\n", "")

def test_root_not_found(client: FlaskClient) -> None:
    """Verify that the root endpoint returns 404."""
    response = client.get("/")
    assert response.status_code == 404


def test_validate_without_cert_header(client: FlaskClient) -> None:
    """Verify that the /validate endpoint returns 403 without Cert header."""
    response = client.get("/validate")
    assert response.status_code == 403


def test_validate_with_valid_cert_header(client: FlaskClient) -> None:
    """Verify that the /validate endpoint returns 200 with correct Cert header."""
    headers = {
        "X-Forwarded-Tls-Client-Cert": trust_anchor_example_cert_pem_str,
    }
    response = client.get("/validate", headers=headers)
    assert response.status_code == 200


def test_validate_with_invalid_cert_header(client: FlaskClient) -> None:
    """Verify that the /validate endpoint returns 403 with incorrect DN header."""
    bad_pem_str = trust_anchor_example_cert_pem_str.replace("M","Z")
    headers = {
        "X-Forwarded-Tls-Client-Cert": bad_pem_str,
    }
    response = client.get("/validate", headers=headers)
    assert response.status_code == 403

