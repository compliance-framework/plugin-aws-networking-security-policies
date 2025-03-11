package compliance_framework.template.aws._deny_unrestricted_egress

violation[{
  "title": "Egress rules should not allow unrestricted outbound traffic",
  "description": "Outbound traffic should be limited to prevent data exfiltration.",
}] if {
  input.IpPermissionsEgress[_].IpRanges[_].CidrIp == "0.0.0.0/0"
}
