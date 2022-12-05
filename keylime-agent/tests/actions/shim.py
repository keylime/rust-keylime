#!/usr/bin/python3
'''
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Keylime Authors
'''

import argparse
import asyncio
import importlib
import json
import os
import sys


def main():
    # Parse arguments to get action name and input json file path
    parser = argparse.ArgumentParser()
    parser.add_argument('action', type=str, help='The revocation action to be'
                        ' executed. The module must provide an \'execute()\''
                        ' method which receives a JSON as argument')
    parser.add_argument('json_file', type=str, help='Input file')

    args = parser.parse_args()

    with open(args.json_file, 'r') as f:
        input_json = json.load(f)

        try:
            module = importlib.import_module(args.action)
            execute = getattr(module, 'execute')
            asyncio.run(execute(input_json))
        except Exception as e:
            print("Exception during execution of revocation action {}: {}".format(
                args.action, e), file=sys.stderr)


if __name__ == "__main__":
    main()
