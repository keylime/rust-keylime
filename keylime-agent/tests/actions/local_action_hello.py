'''
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Keylime Authors
'''


async def execute(revocation):
    try:
        value = revocation['hello']
        print(value)
    except Exception as e:
        raise Exception(
            "The provided dictionary does not contain the 'hello' key")
