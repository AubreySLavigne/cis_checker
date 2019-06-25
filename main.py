#!/usr/bin/env python3

import json

import boto3
import botocore


def main() -> None:

    res = []

    # 2.8 Ensure rotation for customer created CMKs is enabled (Scored)
    client = boto3.client('kms')
    keys = client.list_keys().get('Keys')
    for key in keys:
        try:
            key_id = key.get('KeyId')
            status = client.get_key_rotation_status(KeyId=key_id)
            if not status.get('KeyRotationEnabled'):
                res.append({
                    'benchmark': '2.8',
                    'key_id':    key_id,
                    'reason':    "KeyRotationEnabled is not set"
                })
        except botocore.exceptions.ClientError as err:
            res.append({
                'benchmark': '2.8',
                'key_id':    key_id,
                'reason':    str(err)
            })

    # Print Results
    print(json.dumps(res))


if __name__ == '__main__':
    main()
