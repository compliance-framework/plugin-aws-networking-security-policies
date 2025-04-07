package compliance_framework.deny_open_rdp

violation[{}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/0"
  input.IpPermissions[_].ToPort == 3389
}

title := "RDP (port 3389) should be restricted"
description := "RDP access should not be open to the wider internet, and should be limited to trusted sources"
