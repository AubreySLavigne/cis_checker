#!/usr/bin/env python3

import json

import boto3
import botocore


def port_in_range(target: int, lower_bound: int, upper_bound: int) -> bool:
    """
    Returns True if the 'target' port is with the rule:
    lower_bound <= target <= upper_bound

    Returns True if either bound is -1 (signalling 'any port').

    Otherwise returns false.
    """
    if lower_bound == -1:
        return True
    if upper_bound == -1:
        return True
    if lower_bound <= target <= upper_bound:
        return True

    return False


def main() -> None:

    session = boto3.session.Session(profile_name='default')

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
                    'reason':    'KeyRotationEnabled is not set'
                })
        except botocore.exceptions.ClientError as err:
            res.append({
                'benchmark': '2.8',
                'key_id':    key_id,
                'reason':    str(err)
            })

    # 4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)
    client = session.client('ec2')
    security_groups = client.describe_security_groups().get('SecurityGroups')
    for group in security_groups:
        group_id = group.get('GroupId')
        ingress_rules = group.get('IpPermissions')
        for rule in ingress_rules:

            from_port = rule.get('FromPort')
            if from_port is None:
                continue
            to_port = rule.get('FromPort')
            if to_port is None:
                continue

            if not port_in_range(22, from_port, to_port):
                continue

            for ip_range in rule.get('IpRanges'):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    res.append({
                        'benchmark': '4.1',
                        'key_id':    group_id,
                        'reason':    "Security Group includes port 22 and has IP Range '0.0.0.0/0'"
                    })

    # Print Results
    print(json.dumps(res))


if __name__ == '__main__':
    main()
