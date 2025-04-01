package compliance_framework.template.aws._deny_unrestricted_egress

# METADATA
# title: Ensure egress rules do not allow unrestricted outbound traffic
# description: Verifies that outbound traffic is limited to specific IP ranges to prevent data exfiltration risks.
# custom:
#   controls:
#     - SAMA_CSF_1.0
#     - SAMA_ITGF_1.0
#     - SAMA_CCF_1.0
#     - SAMA_RMG_1.0
#   schedule: "* * * * * *"

controls := [
    # SAMA Cyber Security Framework v1.0
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.6", # Data Protection
        "statement-ids": [
            "6", # Ensure proper controls are in place to prevent unauthorized data exfiltration.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/CyberSecurity/Cyber%20Security%20Framework.pdf#page=36"
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "2.2.5", # Data Security
        "statement-ids": [
            "1", # Ensure that egress traffic is restricted to prevent unauthorized data transmission.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/ITGovernance/ITGovernanceFramework.pdf#page=40"
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "3.2.4", # Data Protection and Encryption
        "statement-ids": [
            "2", # Limit outbound traffic to specific destinations to reduce the risk of data exfiltration.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/CloudComputing/CloudComputingFramework.pdf#page=28"
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "4.2.1", # Risk Management for External Exposure
        "statement-ids": [
            "3", # Identify and mitigate risks associated with outbound traffic to the internet.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/RiskManagement/RiskManagementGuidelines.pdf#page=22"
    },
]

violation[{
  "title": "Egress rules should not allow unrestricted outbound traffic",
  "description": "Outbound traffic should be limited to prevent data exfiltration.",
}] if {
  input.IpPermissionsEgress[_].IpRanges[_].CidrIp == "0.0.0.0/0"
}
