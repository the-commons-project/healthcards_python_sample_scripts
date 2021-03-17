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
    print(input_jwt)

    # payload = input_jwt.split('.')[1]
    # payload_string = base64.standard_b64decode(payload).decode(encoding='utf-8')
    # print(payload_string)

if __name__ == "__main__":
    main()