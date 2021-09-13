import json
import argparse
import base64
import utils

def main():
    parser = argparse.ArgumentParser(description='Decodes a vc')
    parser.add_argument('output_file', help='Output file')
    parser.add_argument('input', help='Input resource')
    args = parser.parse_args()

    numeric_encoded_payload = utils.encode_to_numeric(args.input)
    qr_img = utils.create_shc_qr_code(numeric_encoded_payload)
    with open(args.output_file, 'wb') as outfile:
        qr_img.save(outfile)

if __name__ == "__main__":
    main()


