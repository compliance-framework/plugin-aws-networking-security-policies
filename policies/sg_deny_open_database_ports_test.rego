package compliance_framework.template.aws._deny_open_database_ports_test

import data.compliance_framework.template.aws._deny_open_database_ports

test_violation_open_database_ports if {
  _deny_open_database_ports.violation[_] with input as {
    "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "ToPort": 3306}]
  }
}