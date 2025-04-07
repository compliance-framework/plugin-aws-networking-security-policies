package compliance_framework.deny_open_ssh

violation[{}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/0"
  input.IpPermissions[_].ToPort == 22
}

title := "SSH (port 22) should be restricted"
description := "SSH access should not be open to the wider internet, and should be limited to trusted sources"
