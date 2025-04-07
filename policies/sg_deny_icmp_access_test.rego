package compliance_framework.deny_icmp_access

test_violation_icmp_access if {
  count(violation) == 1 with input as {
    "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "IpProtocol": "icmp"}]
  }
}
