"""EC2's transport (aws.https): a request goes as the plugin signed it, nothing added from the environment."""
from __future__ import annotations

import requests

from plugin_platform_ec2 import aws

REAL_HTTPS = aws.https  # the conftest refuses aws.https in every test: this one sends through a stand-in Session.send


def test_a_netrc_entry_or_a_proxy_never_reaches_a_signed_request(tmp_path, monkeypatch):
    """The review of 2026-11-21 (item 26), a P1: requests.request read ~/.netrc, so a `default` entry replaced the
    SigV4 Authorization with Basic credentials sent to AWS; proxies and CA bundles came from the variables too."""
    netrc = tmp_path / "netrc"
    netrc.write_text("default login someone password hunter22\n")
    monkeypatch.setenv("NETRC", str(netrc))
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "ca.pem"))
    sent = []

    def send(self, request, **kw):
        sent.append((request, kw))
        r = requests.Response()
        r.status_code, r._content, r.url = 200, b"<ok/>", request.url
        return r

    monkeypatch.setattr(requests.Session, "send", send)
    signed = {"Authorization": "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261124/us-east-1/ec2/aws4_request, ..."}
    status, _headers, body = REAL_HTTPS("GET", "https://ec2.us-east-1.amazonaws.com/?Action=DescribeInstances", signed,
                                       None, 5.0)
    assert (status, body) == (200, b"<ok/>") and len(sent) == 1
    request, kw = sent[0]
    assert request.headers["Authorization"].startswith("AWS4-HMAC-SHA256")
    assert not kw.get("proxies") and kw.get("verify") in (True, None)
