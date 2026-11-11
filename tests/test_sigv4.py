"""The SigV4 signing, against AWS's published examples: the Amazon S3 User Guide's "Signature Calculations for the
Authorization Header: Transferring Payload in a Single Chunk" (its Examples: GET Object, PUT Object, GET Bucket Lifecycle,
Get Bucket), each canonical request, string to sign and signature as AWS prints them; then the signer as the clients use
it (EC2's and Route 53's scopes, a session token, what is signed)."""
from __future__ import annotations

import pytest

from plugin_platform_ec2.sigv4 import (EMPTY_SHA256, Credentials, Signer, aws_scope, canonical_query, sha256_hex, sign,
                                       signing_key, uri_encode)

# AWS's example credentials and request time (the S3 User Guide's examples)
AWS = Credentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
WHEN = "20130524T000000Z"
BUCKET = "examplebucket.s3.amazonaws.com"
EXAMPLES = [  # (method, url, headers signed, body, canonical request, string to sign's last line, signature)
    ("GET", f"https://{BUCKET}/test.txt",
     {"host": BUCKET, "range": "bytes=0-9", "x-amz-content-sha256": EMPTY_SHA256, "x-amz-date": WHEN}, b"",
     f"GET\n/test.txt\n\nhost:{BUCKET}\nrange:bytes=0-9\nx-amz-content-sha256:{EMPTY_SHA256}\nx-amz-date:{WHEN}\n\n"
     f"host;range;x-amz-content-sha256;x-amz-date\n{EMPTY_SHA256}",
     "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972",
     "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"),
    ("PUT", f"https://{BUCKET}/test$file.text",
     {"date": "Fri, 24 May 2013 00:00:00 GMT", "host": BUCKET,
      "x-amz-content-sha256": "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072", "x-amz-date": WHEN,
      "x-amz-storage-class": "REDUCED_REDUNDANCY"}, b"Welcome to Amazon S3.",
     f"PUT\n/test%24file.text\n\ndate:Fri, 24 May 2013 00:00:00 GMT\nhost:{BUCKET}\n"
     "x-amz-content-sha256:44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072\n"
     f"x-amz-date:{WHEN}\nx-amz-storage-class:REDUCED_REDUNDANCY\n\n"
     "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class\n"
     "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
     "9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d",
     "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"),
    ("GET", f"https://{BUCKET}/?lifecycle",
     {"host": BUCKET, "x-amz-content-sha256": EMPTY_SHA256, "x-amz-date": WHEN}, b"",
     f"GET\n/\nlifecycle=\nhost:{BUCKET}\nx-amz-content-sha256:{EMPTY_SHA256}\nx-amz-date:{WHEN}\n\n"
     f"host;x-amz-content-sha256;x-amz-date\n{EMPTY_SHA256}",
     "9766c798316ff2757b517bc739a67f6213b4ab36dd5da2f94eaebf79c77395ca",
     "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"),
    ("GET", f"https://{BUCKET}/?max-keys=2&prefix=J",
     {"host": BUCKET, "x-amz-content-sha256": EMPTY_SHA256, "x-amz-date": WHEN}, b"",
     f"GET\n/\nmax-keys=2&prefix=J\nhost:{BUCKET}\nx-amz-content-sha256:{EMPTY_SHA256}\nx-amz-date:{WHEN}\n\n"
     f"host;x-amz-content-sha256;x-amz-date\n{EMPTY_SHA256}",
     "df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7",
     "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"),
]


@pytest.mark.parametrize("method, url, headers, body, request_, hashed, signature", EXAMPLES,
                         ids=["GET Object", "PUT Object", "GET Bucket Lifecycle", "Get Bucket (List Objects)"])
def test_the_signature_is_awss_own_for_its_published_examples(method, url, headers, body, request_, hashed, signature):
    made = sign(method, url, headers, body, AWS, "us-east-1", "s3", WHEN)
    assert made.canonical_request == request_
    assert made.string_to_sign == f"AWS4-HMAC-SHA256\n{WHEN}\n20130524/us-east-1/s3/aws4_request\n{hashed}"
    assert sha256_hex(made.canonical_request) == hashed
    assert made.signature == signature
    # the Authorization header AWS prints (its commas: AWS takes them with or without a space after)
    assert made.authorization.replace(", ", ",") == (f"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/"
                                                     f"s3/aws4_request,SignedHeaders={made.signed_headers},Signature={signature}")


def test_the_payload_hash_and_the_encoding_are_awss():
    assert sha256_hex(b"Welcome to Amazon S3.") == "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
    assert sha256_hex(b"") == EMPTY_SHA256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert uri_encode("a b+c/d~e_f-g.h*") == "a%20b%2Bc%2Fd~e_f-g.h%2A"  # %20, never +; / encoded in a value
    assert uri_encode("/a b/c", slash=False) == "/a%20b/c" and uri_encode("é") == "%C3%A9"
    assert canonical_query("b=2&a=1&a=0&c") == "a=0&a=1&b=2&c="  # sorted by name then value; a name alone "name="
    assert canonical_query("Filter.1.Name=tag%3AName&Action=DescribeInstances") == \
        "Action=DescribeInstances&Filter.1.Name=tag%3AName"
    # the signing key chained from "AWS4" + the secret over the date, region, service and aws4_request
    import hashlib
    import hmac

    k = hmac.new(b"AWS4" + AWS.secret_key.encode(), b"20130524", hashlib.sha256).digest()
    for part in (b"us-east-1", b"s3", b"aws4_request"):
        k = hmac.new(k, part, hashlib.sha256).digest()
    assert signing_key(AWS.secret_key, "20130524", "us-east-1", "s3") == k


def test_the_signer_signs_each_request_for_its_region_and_service_with_its_token():
    creds = Credentials("AKIA0TESTKEY0000ID01", "secret-0123456789", token="TOKEN-0123")
    signer = Signer(creds, clock=lambda: 1_700_000_000.0)  # 2023-11-14T22:13:20Z
    out = signer("POST", "https://ec2.eu-west-1.amazonaws.com/", {"Accept": "application/xml", "User-Agent": "x",
                                                                  "Content-Type": "application/x-www-form-urlencoded"},
                 b"Action=DescribeRegions&Version=2016-11-15")
    assert out["X-Amz-Date"] == "20231114T221320Z" and out["X-Amz-Security-Token"] == "TOKEN-0123"
    assert out["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIA0TESTKEY0000ID01/20231114/eu-west-1/ec2/"
                                           "aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, ")
    assert out["Accept"] == "application/xml" and "secret-0123456789" not in str(out)  # the secret is never sent
    again = sign("POST", "https://ec2.eu-west-1.amazonaws.com/",
                 {"content-type": "application/x-www-form-urlencoded", "host": "ec2.eu-west-1.amazonaws.com",
                  "x-amz-date": "20231114T221320Z", "x-amz-security-token": "TOKEN-0123"},
                 b"Action=DescribeRegions&Version=2016-11-15", creds, "eu-west-1", "ec2", "20231114T221320Z")
    assert out["Authorization"] == again.authorization
    r53 = signer("GET", "https://route53.amazonaws.com/2013-04-01/hostedzone?maxitems=100", {}, b"")
    assert "/20231114/us-east-1/route53/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token," in r53["Authorization"]
    assert aws_scope("ec2.ap-southeast-2.amazonaws.com") == ("ap-southeast-2", "ec2")
    with pytest.raises(ValueError, match="none of the endpoints"):
        signer("GET", "https://sts.amazonaws.com/", {}, b"")  # nothing but EC2 and Route 53 is signed for
