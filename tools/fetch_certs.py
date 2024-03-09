import requests
import csv
from io import StringIO
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import struct
import json
import argparse

# Format: CCADB Record Creation Date, SHA-256 Fingerprint, Subject Key Identifier, Authority Key Identifier, Root or Intermediate Certificate Record, X.509 Certificate PEM
REPORT_URL = "https://ccadb.my.salesforce-sites.com/ccadb/WebTrustListAsOf?ListDate={}"
DATE_ADDITION_COL = 'CCADB Record Creation Date'
CERT_PEM_COL = 'X.509 Certificate PEM'

class IdentifierAllocator:
    # Prefix should be a byte string.
    def __init__(self, prefix):
        self.prefix = prefix
        self.position = 0

    def getIdentifier(self):
        result = self.prefix + struct.pack('>H',self.position)
        self.position += 1
        return result


def get_webtrust_certs(list_date):
    output = []
    url = REPORT_URL.format(list_date)
    response = requests.get(url,timeout=10)
    response.raise_for_status()
    csv_data = response.text
    for r in csv.DictReader(StringIO(csv_data)):
        timestamp = datetime.strptime(r[DATE_ADDITION_COL], '%Y-%m-%dT%H:%M:%SZ')
        cert = x509.load_pem_x509_certificate(r[CERT_PEM_COL].encode('ascii'), default_backend())
        certDer = cert.public_bytes(serialization.Encoding.DER)
        output.append((timestamp,certDer))
    return output

def create_cert_dict(certs):
    certs.sort(key = lambda x : x[0] )
    output = dict()
    idAlloc = IdentifierAllocator(b'\xff')
    for (_,der) in certs:
        idHex = idAlloc.getIdentifier().hex()
        output[idHex] = der.hex()
    return output

if __name__ == "__main__":
    today = datetime.now().strftime("%Y-%m-%d")
    parser = argparse.ArgumentParser(description="Builds a map from identifiers to WebPKI Intermediate and Root Certificates")
    parser.add_argument("-d", "--date", help="Specify the date you want the list as-of (YYYY-MM-DD format)", type=str,default=today)
    parser.add_argument("-o", "--output", help="Specify the output file path", type=str,default="output.json")
    args = parser.parse_args()

    certs = get_webtrust_certs(args.date)
    print(f"Fetched {len(certs)} certificates")
    certs = create_cert_dict(certs)
    wrapper = dict()
    wrapper['data'] = certs
    wrapper['list_date'] = args.date
    wrapper['creation_date'] = today
    with open(args.output,'w') as json_file:
        json.dump(wrapper,json_file,indent=4)
    print(f"Output to {args.output}")