package compliance_framework.template.aws._deny_open_ssh_test

import data.compliance_framework.template.aws._deny_open_ssh

test_violation_open_ssh if {
  _deny_open_ssh.violation[_] with input as {
    "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "ToPort": 22}]
  }
}
