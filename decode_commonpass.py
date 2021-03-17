import json
import argparse
import base64
import utils

def main():
    parser = argparse.ArgumentParser(description='Decodes a CommonPass')
    parser.add_argument('input', help='Input CommonPass URL')
    args = parser.parse_args()

    numeric_payload = args.input.split('#')[1]

    input_jwt = utils.decode_from_numeric(numeric_payload)

    payload_dict = utils.decode_vc(input_jwt, verify=False)

    print(json.dumps(payload_dict, indent=4))

if __name__ == "__main__":
    main()