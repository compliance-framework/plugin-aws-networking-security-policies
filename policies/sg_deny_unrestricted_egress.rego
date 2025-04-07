package compliance_framework.deny_unrestricted_egress

violation[{}] if {
  input.IpPermissionsEgress[_].IpRanges[_].CidrIp == "0.0.0.0/0"
}

title := "Egress should be restricted"
description := "Egress rules should be limited to trusted CIDRs and not opened to the wider internet"
