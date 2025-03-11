package compliance_framework.template.aws._deny_unrestricted_egress_test

import data.compliance_framework.template.aws._deny_unrestricted_egress

test_violation_unrestricted_egress if {
  _deny_unrestricted_egress.violation[_] with input as {
    "IpPermissionsEgress": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
  }
}