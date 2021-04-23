#!/usr/bin/env python
import argparse
import json
import time
import secrets
import shc.utils


def main():

    parser = argparse.ArgumentParser(description='Encodes a vc file into a QR code')
    parser.add_argument('input_file', help='Sample VC fixture file')
    parser.add_argument('output_file', help='Output file')

    args = parser.parse_args()
    with open(args.input_file, 'r') as input_file:
        fhir_backed_vc = json.load(input_file).get('verifiableCredential')[0]

    numeric_encoded_payload = utils.encode_to_numeric(fhir_backed_vc)
    qr_img = utils.create_qr_code(numeric_encoded_payload)
    with open(args.output_file, 'wb') as outfile:
        qr_img.save(outfile)


if __name__ == "__main__":
    main()
