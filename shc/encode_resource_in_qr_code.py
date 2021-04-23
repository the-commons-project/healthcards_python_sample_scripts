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

    numeric_encoded_payload = utils.encode_to_numeric(vc_jws)
    qr_img = utils.create_qr_code(numeric_encoded_payload)
    with open(args.output_file, 'wb') as outfile:
        qr_img.save(outfile)


if __name__ == "__main__":
    main()
