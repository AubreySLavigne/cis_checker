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


class Violations(object):
    """
    Manages Results from the Checks
    """
    def __init__(self):
        self.results = {}

    def add(self, benchmark: str, reason: str, info: dict) -> None:
        """
        Adds the results from the benchmark
        """
        if benchmark not in self.results:
            self.results[benchmark] = []

        self.results[benchmark].append({
            'reason': reason,
            'info':   info
        })


class CISChecker(object):
    """
    Object with API to consolidate CIS Benchmarks
    """
    def __init__(self):
        self.session = boto3.session.Session(profile_name='default')
        self.res = Violations()

    def check_2_8(self) -> None:
        """
        2.8 Ensure rotation for customer created CMKs is enabled (Scored)
        """
        client = self.session.client('kms')
        keys = client.list_keys().get('Keys')
        for key in keys:
            try:
                key_id = key.get('KeyId')
                status = client.get_key_rotation_status(KeyId=key_id)
                if not status.get('KeyRotationEnabled'):
                    self.res.add('2.8', 'KeyRotationEnabled is not set', {
                        'key_id':    key_id
                    })
            except botocore.exceptions.ClientError as err:
                self.res.add('2.8', str(err), {
                    'key_id':    key_id
                })

    def check_4_1(self) -> None:
        """
        4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)
        """
        client = self.session.client('ec2')
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
                        self.res.add('4.1',
                                     "Security Group includes port 22 and has IP Range '0.0.0.0/0'", {
                                         'group_id':    group_id
                                     })

    def check_4_2(self) -> None:
        """
        4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)
        """
        client = self.session.client('ec2')
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

                if not port_in_range(3389, from_port, to_port):
                    continue

                for ip_range in rule.get('IpRanges'):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        self.res.add('4.2',
                                     "Security Group includes port 3389 and has IP Range '0.0.0.0/0'", {
                                         'group_id':    group_id
                                     })


def main() -> None:

    checker = CISChecker()

    checker.check_2_8()
    checker.check_4_1()
    checker.check_4_2()

    # Print Results
    print(json.dumps(checker.res.results))


if __name__ == '__main__':
    main()
