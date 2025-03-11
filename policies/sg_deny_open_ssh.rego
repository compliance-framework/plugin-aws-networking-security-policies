package compliance_framework.template.aws._deny_open_ssh

violation[{
  "title": "SSH (port 22) should not be open to the world",
  "description": "Security group allows SSH access (port 22) from 0.0.0.0/0, which poses a security risk.",
}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/0"
  input.IpPermissions[_].ToPort == 22
}
