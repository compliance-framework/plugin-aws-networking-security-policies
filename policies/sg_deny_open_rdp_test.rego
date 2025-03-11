package compliance_framework.template.aws._deny_open_rdp_test

import data.compliance_framework.template.aws._deny_open_rdp

test_violation_open_rdp if {
  _deny_open_rdp.violation[_] with input as {
    "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "ToPort": 3389}]
  }
}
