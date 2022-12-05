#!/usr/bin/python3
'''
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Keylime Authors
'''

import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('json_file')
    args = parser.parse_args()

    with open(args.json_file, 'r') as f:
        input_json = json.load(f)
        value = input_json['hello']

    print(value)


if __name__ == "__main__":
    main()

