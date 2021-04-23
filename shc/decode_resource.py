#!/usr/bin/env python
import json
import argparse
import shc.utils


def main():
    parser = argparse.ArgumentParser(description='Decodes a vc')
    parser.add_argument('input_file', help='Input file')

    args = parser.parse_args()
    with open(args.input_file, 'r') as input_file:
        fhir_backed_vc = json.load(input_file).get('verifiableCredential')[0]
        payload_dict = utils.decode_vc(fhir_backed_vc)

    print(json.dumps(payload_dict, indent=4))


if __name__ == "__main__":
    main()
