package compliance_framework.deny_open_database_ports

db_ports := {3306, 5432, 1433}

violation[{}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/0"
  db_ports[input.IpPermissions[_].ToPort]
}

title := "Database port access should be restricted"
description := "Database ports should not be opened to the wider internet, and should be restricted to trusted sources"