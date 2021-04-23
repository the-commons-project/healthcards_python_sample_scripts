#!/usr/bin/env python
import argparse
import json
import time
import secrets
import shc.utils


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

        # since we're using a static file to form the payload
        # it needs to be modified a bit
        now = int(time.time())
        payload['iss'] = args.issuer
        payload['iat'] = now
        vc_jws = utils.encode_vc(payload, private_signing_key, kid)

    # this is the general format for a FHIR backed vc file, this is subject to change
    with open(args.output_file, 'w') as outfile:
        output_dict = {
            'verifiableCredential': [vc_jws]
        }
        json.dump(output_dict, outfile)


if __name__ == "__main__":
    main()
