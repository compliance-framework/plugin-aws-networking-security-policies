package compliance_framework.template.aws._deny_icmp_access_test

import data.compliance_framework.template.aws._deny_icmp_access

test_violation_icmp_access if {
  _deny_icmp_access.violation[_] with input as {
    "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "IpProtocol": "icmp"}]
  }
}
