#!/usr/bin/python3

import sys
import json

input_data = sys.stdin.read()
input_json = json.loads(input_data)

value = input_json.get('hello')

print(value)
