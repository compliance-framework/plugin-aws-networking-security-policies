package compliance_framework.deny_permissive_cidr

violation[{}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/0"
}

violation[{}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/1"
}

violation[{}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/2"
}

title := "CIDR Ingress should be restricted"
description := "Ingress should be limited to trusted CIDRs and not opened to the wider internet"
