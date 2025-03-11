package compliance_framework.template.aws._deny_icmp_access

violation[{
  "title": "ICMP access should be restricted",
  "description": "Security group allows unrestricted ICMP traffic, which may pose a security risk.",
}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/0"
  input.IpPermissions[_].IpProtocol == "icmp"
}
