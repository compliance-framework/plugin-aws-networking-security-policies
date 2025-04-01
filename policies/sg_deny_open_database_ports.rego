package compliance_framework.template.aws._deny_open_database_ports

# METADATA
# title: Database port should not be open to the world
# description: Verifies that database ports are not publicly accessible to prevent data exposure.
# custom:
#   controls:
#     - SAMA_CSF_1.0
#     - SAMA_ITGF_1.0
#     - SAMA_RMG_1.0
#     - SAMA_CCF_1.0
#   schedule: "* * * * * *"

controls := [
    # SAMA Cyber Security Framework v1.0
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.6", # Data Protection
        "statement-ids": [
            "1", # Ensure proper encryption and access control to protect sensitive data.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/CyberSecurity/Cyber%20Security%20Framework.pdf#page=33"
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "2.2.5", # Access Control Management
        "statement-ids": [
            "4", # Ensure that sensitive ports are restricted and access is logged and monitored.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/ITGovernance/ITGovernanceFramework.pdf#page=42"
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "4.2.1", # Security Risk Management
        "statement-ids": [
            "2", # Ensure mitigation of risks associated with publicly accessible ports.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/RiskManagement/RiskManagementGuidelines.pdf#page=25"
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "2.1.4", # Network Security in Cloud
        "statement-ids": [
            "5", # Ensure that cloud-based databases are not exposed to the internet unnecessarily.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/CloudComputing/CloudComputingFramework.pdf#page=20"
    },
]

db_ports := {3306, 5432, 1433}

violation[{
  "title": sprintf("Database port %d should not be open to the world", [input.IpPermissions[_].ToPort]),
  "description": "Publicly accessible database increases the risk of data exposure.",
}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/0"
  db_ports[input.IpPermissions[_].ToPort]
}
