#!/usr/bin/python3
'''
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Keylime Authors
'''

import sys
import json

input_data = sys.stdin.read()
input_json = json.loads(input_data)

value = input_json['hello']

print(value)
