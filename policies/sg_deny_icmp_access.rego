package compliance_framework.template.aws._deny_icmp_access

# METADATA
# title: ICMP access should be restricted
# description: Security group allows unrestricted ICMP traffic, which may pose a security risk.
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
        "control-id": "3.3.9", # Network Security
        "statement-ids": [
            "4", # Ensure proper firewall and access control lists to restrict unnecessary inbound and outbound traffic.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/CyberSecurity/Cyber%20Security%20Framework.pdf#page=41"
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "2.2.3", # Network Access Control
        "statement-ids": [
            "5", # Ensure that security measures are implemented to prevent unauthorized access to the network.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/ITGovernance/ITGovernanceFramework.pdf#page=32"
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "4.2.2", # Risk Control
        "statement-ids": [
            "3", # Ensure proper network monitoring and traffic control to mitigate security risks.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/RiskManagement/RiskManagementGuidelines.pdf#page=28"
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "2.1.5", # Cloud Security
        "statement-ids": [
            "4", # Ensure appropriate controls to restrict unauthorized access to cloud resources.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/CloudComputing/CloudComputingFramework.pdf#page=25"
    },
]

violation[{
  "title": "ICMP access should be restricted",
  "description": "Security group allows unrestricted ICMP traffic, which may pose a security risk.",
}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/0"
  input.IpPermissions[_].IpProtocol == "icmp"
}
