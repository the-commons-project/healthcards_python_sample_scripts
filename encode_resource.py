from jose import jws
import argparse
import json
import time
import secrets
import utils

def encode_vc(payload, private_signing_key, kid):

    payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    compressed_payload = utils.deflate(payload_bytes)

    headers = {"kid": kid, 'zip': 'DEF'}
    return jws.sign(compressed_payload, private_signing_key, headers=headers, algorithm='ES256')

def main():
    parser = argparse.ArgumentParser(description='Encodes a vc')
    parser.add_argument('private_keyset_file', help='Private keyset file')
    parser.add_argument('issuer', help='Issuer')
    parser.add_argument('input_file', help='Sample VC fixture file')
    parser.add_argument('output_file', help='Output file')

    args = parser.parse_args()
    (kid, private_signing_key) = utils.load_private_key_from_file(
        args.private_keyset_file,
        'sig',
        'ES256'
    )

    with open(args.input_file, 'r') as input_file:
        payload = json.load(input_file)

        ##since we're using a static file to form the payload
        ## it needs to be modified a bit
        now = int(time.time())
        payload['iss'] = args.issuer
        payload['iat'] = now
        vc_jws = encode_vc(payload, private_signing_key, kid)

    ## this is the general format for a FHIR backed vc file, this is subject to change
    with open(args.output_file, 'w') as outfile:
        output_dict = {
            'verifiableCredential': [vc_jws]
        }
        json.dump(output_dict, outfile)

if __name__ == "__main__":
    main()