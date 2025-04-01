package compliance_framework.template.aws._deny_permissive_cidr

# METADATA
# title: Ensure security group CIDR blocks are not too permissive
# description: Verifies that security groups do not allow overly broad IP ranges such as 0.0.0.0/0, which increases exposure to security risks.
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
        "control-id": "3.3.9", # Network Security
        "statement-ids": [
            "5", # Ensure that security groups are configured with appropriate access control policies.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/CyberSecurity/Cyber%20Security%20Framework.pdf#page=38"
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "2.2.4", # Access Control
        "statement-ids": [
            "1", # Ensure that access to resources is restricted by IP ranges.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/ITGovernance/ITGovernanceFramework.pdf#page=36"
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "3.1.1", # Secure Network Design
        "statement-ids": [
            "3", # Ensure that access to cloud resources is tightly controlled and not exposed to unnecessary IP ranges.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/CloudComputing/CloudComputingFramework.pdf#page=24"
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "4.1.2", # Risk Management for External Exposure
        "statement-ids": [
            "1", # Ensure risks from overly permissive access are identified and mitigated.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/RiskManagement/RiskManagementGuidelines.pdf#page=17"
    },
]

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
