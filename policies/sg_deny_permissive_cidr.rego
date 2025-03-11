package compliance_framework.template.aws._deny_permissive_cidr

violation[{
  "title": "CIDR block is too permissive",
  "description": "Security group allows overly broad IP ranges, increasing exposure.",
}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/0"
}

violation[{
  "title": "CIDR block is too permissive",
  "description": "Security group allows overly broad IP ranges, increasing exposure.",
}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/1"
}

violation[{
  "title": "CIDR block is too permissive",
  "description": "Security group allows overly broad IP ranges, increasing exposure.",
}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/2"
}
