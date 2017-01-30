#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re, time
import logging
import base64, hashlib
import binascii, textwrap, json, copy
from subprocess import Popen, PIPE
try: from urllib.request import urlopen         # Python 3
except ImportError: from urllib2 import urlopen # Python 2

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

class ACMEAccount(object):
    # Account key for ACME
    def __init__(self, account_key):
        self.account_key = account_key  # path for account key
        self._jwk = None
        self._fingerprint = None

    def _b64(self, b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    @property
    def jwk(self):
        # Generate JWK(JSON Web Key)
        if self._jwk: return self._jwk

        # Get modulus and publicExponent from account key
        p = Popen(["openssl", "rsa", "-in", self.account_key, "-noout", "-text"], stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        if p.returncode != 0: raise IOError("OpenSSL Error: %s" % err)
        pubn, pube = re.search(r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)", out, re.MULTILINE|re.DOTALL).groups()
        pubn = re.sub(r"[\s:]", "", pubn)
        pube = "{0:x}".format(int(pube))
        pube = "0{0}".format(pube) if len(pube) % 2 else pube
        self._jwk = {
            "kty": "RSA",                               # Key type
            "n":   self._b64(binascii.unhexlify(pubn)), # modulus
            "e":   self._b64(binascii.unhexlify(pube)), # public exponent
        }
        return self._jwk

    @property
    def fingerprint(self):
        # Calculate fingerprint of access key
        if self._fingerprint: return self._fingerprint
        akey_json = json.dumps(self.jwk, sort_keys=True, separators=(',', ':'))
        self._fingerprint = self._b64(hashlib.sha256(akey_json).digest())
        return self._fingerprint

    def sign(self, s):
        # Sign input string with the account key
        p = Popen(["openssl", "dgst", "-sha256", "-sign", self.account_key], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate(s)
        if p.returncode != 0: raise IOError("OpenSSL Error: %s" % err)
        return out

class ACMEClient(object):
    # Client for ACME
    DEFAULT_DIRECTORY = "https://acme-v01.api.letsencrypt.org/directory"    # endpoint for 'directory' resource

    def __init__(self, account_key, log=LOGGER, directory=DEFAULT_DIRECTORY):
        self._nonce = None  # NONCE value
        self.account = ACMEAccount(account_key)
        self.directory_endpoint = directory
        self.resources = self._get_resources()
        self.log = log

    def _get_resources(self):
        # Get endpoints from 'directory'
        ua = urlopen(self.directory_endpoint)
        self._nonce = ua.headers["Replay-Nonce"]
        return json.load(ua)

    def _b64(self, b):
        # encode into URL safe base64
        return base64.urlsafe_b64encode(b).replace("=", "")

    @property
    def nonce(self):
        # Return NONCE and clear the NONCE
        if not self._nonce:
            raise RuntimeError("No NONCE provided.")
        nonce = self._nonce
        self._nonce = None
        return nonce

    def read_domains(self, csr):
        # Read domain names from CN of CSR
        # Reading SAN has not been implemented yet.
        p = Popen(["openssl", "req", "-in", csr, "-noout", "-subject"], stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        m = re.search(r"/CN=([\w\.-]+)", out)
        return [m.group(1)]

    def send_request(self, url, payload):
        # Send protected request to the specified URL
        # New NONCE will be obtained the response.
        protected = {"alg": "RS256", "jwk": self.account.jwk, "nonce": self.nonce}
        data = {
            "protected": self._b64(json.dumps(protected)),
            "payload":   self._b64(json.dumps(payload)),
        }
        signature = self.account.sign("{0}.{1}".format(data["protected"], data["payload"]))
        data["signature"] = self._b64(signature)

        try:
            res = urlopen(url, json.dumps(data))
            return res.getcode(), res.read()
        except IOError as e:
            res = e
            return getattr(e, "code", None), getattr(e, "read", e.__str__)()
        finally:
            self._nonce = res.headers["Replay-Nonce"]

    def register_account(self):
        # Register account key
        self.log.info("Registering account...")
        endpoint = self.resources["new-reg"]
        code, body = self.send_request(endpoint, {
            "resource": "new-reg",
            "agreement": "https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf",
        })

        if code == 201: self.log.info("Registered.")
        elif code == 409: self.log.info("Already registered, ignored.")
        else: raise RuntimeError("Error in 'new-reg': %d %s" % (code, body))

        return code, json.loads(body)

    def get_status(self, domain):
        # Get challenges and status
        endpoint = self.resources["new-authz"]
        code, body = self.send_request(endpoint, {
            "resource": "new-authz",
            "identifier": {"type": "dns", "value": domain},
        })

        if code != 201:
            raise RuntimeError("Error in 'new-authz': %d %s" % (code, body))

        return json.loads(body)

    def is_valid(self, domain):
        # Check status is valid
        info = self.get_status(domain)
        return bool(info["status"] == "valid")

    def get_challenge(self, domain, typename):
        # Get challenge object with typename
        # typename: http-01, dns-01 ...
        info = self.get_status(domain)
        for c in info["challenges"]:
            if c["type"] == typename:
                client = self
                class _Challenge(object):
                    # Challenge object for responding
                    # c = client.get_challenge(DOMAIN, "dns-01")
                    # ... append _acme-challenge record to target domain ...
                    # c.respond()
                    def __init__(self):
                        self.status = c["status"]
                        self.token = c["token"]
                        self.keyauth = "%s.%s" % (self.token, client.account.fingerprint)
                        self.digested_key_authorization = client._b64(hashlib.sha256(self.keyauth).digest())

                    def respond(self):
                        # Respond the challenge
                        code, body = client.send_request(c["uri"], {"resource": "challenge", "keyAuthorization": self.keyauth})
                        if code != 202:
                            raise RuntimeError("Error in 'challenge': %d %s" % (code, body))

                        # Check result of verification by the server
                        while True:
                            time.sleep(10)
                            ua = urlopen(c["uri"])
                            st = json.load(ua)
                            if st["status"] == "pending":  continue
                            if st["status"] == "valid":  break
                            raise RuntimeError("Error in 'verification': %d %s" % (code, json.dumps(st)))

                        return code, json.loads(body)
                return _Challenge()
        raise ValueError("Challenge type '%s' is not found: %s" % (typename, json.dumps(info)))

    def get_certificate(self, csr):
        # Get certificate with CSR
        p = Popen(["openssl", "req", "-in", csr, "-outform", "DER"], stdout=PIPE, stderr=PIPE)
        csr_der, err = p.communicate()
        endpoint = self.resources["new-cert"]
        code, body = self.send_request(endpoint, {
            "resource": "new-cert",
            "csr": self._b64(csr_der),
        })
        if code != 201:
            raise ValueError("Error in 'new-cert': %d %s" % (code, body))

        # Return signed certificate
        self.log.info("Certificate signed, successfully.")
        crt  = "-----BEGIN CERTIFICATE-----\n"
        crt += "\n".join(textwrap.wrap(base64.b64encode(body), 64)) + "\n"
        crt += "-----END CERTIFICATE-----\n"
        return crt

class AWSRoute53(object):
    # AWS Route53 operation
    def __init__(self, region=None, access_key=None, secret_access_key=None):
        # Target recordset: _acme-challenge + <domain>
        # Append token to TXT
        import boto3
        self.client = boto3.client("route53",region_name=region,
            aws_access_key_id=access_key, aws_secret_access_key=secret_access_key)

    def change_record(self, action, zone_id, domain, token):
        # Add/delete _acme_challenge to the domain
        # action: CREATE|DELETE|UPSERT
        res = self.client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Comment": "Create or Delete _acme_challenge",
                "Changes": [{
                    "Action": action,
                    "ResourceRecordSet": {
                        "Name": "_acme-challenge.%s." % domain, "Type": "TXT", "TTL": 300,
                        "ResourceRecords": [{"Value": '"%s"' % token}],
                    }
                }]
            }
        )

    def set_token(self, zone_id, domain, token):
        # Add token to _acme_challenge
        # tk = aws.set_token(ZONE_ID, DOMAIN, TOKEN)
        # ... respond to ACME ...
        # tk.delete()
        aws = self
        class _AWSRoute53Token(object):
            def delete(self):
                aws.delete_token(zone_id, domain, token)
        self.change_record("UPSERT", zone_id, domain, token)
        return _AWSRoute53Token()

    def delete_token(self, zone_id, domain, token):
        # Delete token from _acme_challenge
        return self.change_record("DELETE", zone_id, domain, token)

if __name__ == "__main__":
    import sys, time
    import ConfigParser
    inifile = ConfigParser.SafeConfigParser()
    inifile.read("./config.ini")
    REGION  = inifile.get("aws", "region")
    ZONE_ID = inifile.get("aws", "zoneId")
    ACCKEY  = inifile.get("aws", "accessKey")
    SECKEY  = inifile.get("aws", "secretAccessKey")

    KEYFILE = inifile.get("letsencrypt", "accountKeyFile")
    CSRFILE = inifile.get("letsencrypt", "csrFile")
    CRTFILE = inifile.get("letsencrypt", "certificateFile")

    client = ACMEClient(KEYFILE)
    domain = client.read_domains(CSRFILE)[0]
    client.register_account()
    challenge = client.get_challenge(domain, "dns-01")
    if challenge.status == "valid":
        LOGGER.info(" + Domain '%s' is valid." % domain)
    else:
        LOGGER.info(" + Setting TXT record for _acme-challenge.%s on Route53")
        aws = AWSRoute53(REGION, ACCKEY, SECKEY)
        r53token = aws.set_token(ZONE_ID, domain, challenge.digested_key_authorization)
        LOGGER.info(" + Waiting 120 seconds for responding.")
        time.sleep(120)
        try:
            LOGGER.info(" + Respond the challenge.")
            challenge.respond()
        except Exception, e:
            LOGGER.error("Validation failed for %s\n%s" % (domain, e))
            sys.exit(1)
        finally:
            LOGGER.info(" + Delete TXT record")
            r53token.delete()

    LOGGER.info("Getting certificate")
    with open(CRTFILE, "w") as fh:
        fh.write(client.get_certificate(CSRFILE))
    LOGGER.info("Done.")
