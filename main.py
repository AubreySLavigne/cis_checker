#!/usr/bin/env python3

import argparse
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
    def __init__(self, profile: str, tests: list):
        self.profile = profile
        self.session = boto3.session.Session(profile_name=self.profile)
        self.res = Violations()
        self.tests = tests

    def run(self) -> None:
        """
        Comment
        """
        if '2.1' in self.tests:
            self.check_2_1()
        if '2.3' in self.tests:
            self.check_2_3()
        if '2.6' in self.tests:
            self.check_2_6()
        if '2.8' in self.tests:
            self.check_2_8()
        if '4.1' in self.tests:
            self.check_4_1()
        if '4.2' in self.tests:
            self.check_4_2()

    def check_2_1(self) -> None:
        """
        2.1 Ensure CloudTrail is enabled in all regions (Scored)
        """
        client = self.session.client('cloudtrail')
        trails = client.describe_trails().get('trailList')
        found_passing_selector = False
        names = []

        for trail in trails:
            trail_name = trail.get('Name')
            names.append(trail_name)
            status = client.get_trail_status(Name=trail_name)
            if status.get('IsLogging') is not True:
                self.res.add('2.1', 'Trail must have logging enabled', {
                    'trail_name': trail_name
                })
                continue
            selectors = client.get_event_selectors(TrailName=trail_name).get('EventSelectors')

            for selector in selectors:
                include_management_events = selector.get('IncludeManagementEvents')
                read_write_type = selector.get('ReadWriteType')
                if include_management_events and read_write_type == 'All':
                    found_passing_selector = True

        if not found_passing_selector:
            self.res.add('2.1',
                         'Trail must have selector that includes management'
                         ' event and read_write_type set to "All"', {
                             'trail_names': names
                         })

    def check_2_3(self) -> None:
        """
        2.3 Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible (Scored)
        """
        cloudtrail = self.session.client('cloudtrail')
        s3 = self.session.client('s3')
        trails = cloudtrail.describe_trails().get('trailList')
        for trail in trails:
            bucket_name = trail.get('S3BucketName')
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                grants = acl.get('Grants')
                for grant in grants:
                    grantee = grant.get('Grantee')
                    if 'URI' in grantee:
                        uri = grantee.get('URI')
                        if uri == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            self.res.add('2.3', 'ACL for trail bucket should not have AllUsers principal', {
                                'bucket_name': bucket_name,
                                'trail_name':  trail.get('Name')
                            })
                        if uri == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                            self.res.add('2.3', 'ACL for trail bucket should not have AuthenticatedUsers principal', {
                                'bucket_name': bucket_name,
                                'trail_name':  trail.get('Name')
                            })

                policy = json.loads(s3.get_bucket_policy(Bucket=bucket_name).get('Policy'))
                statements = policy.get('Statement')
                for statement in statements:
                    if statement.get('Effect') != 'Allow':
                        continue
                    principal = statement.get('Principal')
                    if principal == '*' or principal == '{"AWS":"*"}':
                        self.res.add('2.3', 'Bucket Policy should not have wildcard principal', {
                            'bucket_name': bucket_name,
                            'principal':   principal
                        })
            except botocore.exceptions.ClientError as err:
                self.res.add('2.3', str(err), {
                    'bucket_name': bucket_name,
                })

    def check_2_6(self) -> None:
        """
        2.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3
        bucket (Scored)
        """
        cloudtrail = self.session.client('cloudtrail')
        trails = cloudtrail.describe_trails().get('trailList')
        s3 = self.session.client('s3')
        for trail in trails:
            bucket_name = trail.get('S3BucketName')
            trail_name = trail.get('Name')
            try:
                logging = s3.get_bucket_logging(Bucket=bucket_name).get('LoggingEnabled')
                if not logging.get('TargetBucket') or not logging.get('TargetPrefix'):
                    self.res.add('2.6', 'Trail Bucket must have logging enabled', {
                        'bucket_name': bucket_name,
                        'trail_name':  trail_name
                    })
            except botocore.exceptions.ClientError as err:
                self.res.add('2.6', str(err), {
                    'bucket_name': bucket_name,
                    'trail_name':  trail_name
                })

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
                        'key_id': key_id
                    })
            except botocore.exceptions.ClientError as err:
                self.res.add('2.8', str(err), {
                    'key_id': key_id
                })

    def check_open_port(self, benchmark: str, target_port: int) -> None:
        """
        Verifies that not security groups allow ingress from 0.0.0.0/0
        (anywhere) to the port target_port.

        Any violations of this rule are added to the checker's list of Violations
        """
        client = self.session.client('ec2')
        security_groups = client.describe_security_groups().get('SecurityGroups')

        failure_message = f"Security Group includes port {target_port} and has IP Range '0.0.0.0/0'"

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

                if not port_in_range(target_port, from_port, to_port):
                    continue

                for ip_range in rule.get('IpRanges'):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        self.res.add(benchmark, failure_message, {
                            'group_id': group_id
                        })

    def check_4_1(self) -> None:
        """
        4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)
        """
        self.check_open_port('4.1', 22)

    def check_4_2(self) -> None:
        """
        4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)
        """
        self.check_open_port('4.2', 3389)


def main() -> None:

    parser = argparse.ArgumentParser()
    parser.add_argument('-p',
                        '--profiles',
                        type=str,
                        help='Comma-Separated string, listing profiles to be tested')
    args = parser.parse_args()

    if args.profiles:
        profiles = args.profiles.split(',')
    else:
        profiles = ['default']

    results = {}

    for profile in profiles:

        checker = CISChecker(
            profile=profile,
            tests=[
                '2.1',
                '2.3',
                '2.6',
                '2.8',
                '4.1',
                '4.2'
            ])
        checker.run()

        results[profile] = checker.res.results

    # Print Results
    print(json.dumps(results))


if __name__ == '__main__':
    main()
