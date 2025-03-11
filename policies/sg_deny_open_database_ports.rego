package compliance_framework.template.aws._deny_open_database_ports

db_ports := {3306, 5432, 1433}

violation[{
  "title": sprintf("Database port %d should not be open to the world", [input.IpPermissions[_].ToPort]),
  "description": "Publicly accessible database increases the risk of data exposure.",
}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/0"
  db_ports[input.IpPermissions[_].ToPort]
}
