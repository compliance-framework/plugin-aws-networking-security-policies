package compliance_framework.template.aws._deny_open_rdp

violation[{
  "title": "RDP (port 3389) should not be open to the world",
  "description": "Security group allows unrestricted RDP access, which increases the attack surface.",
}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/0"
  input.IpPermissions[_].ToPort == 3389
}