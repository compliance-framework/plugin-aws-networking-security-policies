package compliance_framework.deny_icmp_access

violation[{}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/0"
  input.IpPermissions[_].IpProtocol == "icmp"
}

title := "ICMP access is restricted"
description := "ICMP access should not be opened to the wider internet, but restricted to validated origins"