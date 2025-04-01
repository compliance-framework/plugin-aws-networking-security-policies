package compliance_framework.template.aws._deny_open_ssh

# METADATA
# title: SSH (port 22) should not be open to the world
# description: Verifies that SSH port 22 is not publicly accessible to reduce the attack surface.
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
            "5", # Ensure that services like SSH are not exposed to the public network unnecessarily.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/CyberSecurity/Cyber%20Security%20Framework.pdf#page=38"
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "2.2.4", # Access Control
        "statement-ids": [
            "1", # Ensure that only authorized IP ranges can access services like SSH.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/ITGovernance/ITGovernanceFramework.pdf#page=36"
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "3.1.1", # Secure Network Design
        "statement-ids": [
            "3", # Ensure services that are not needed externally (such as SSH) are isolated from the internet.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/CloudComputing/CloudComputingFramework.pdf#page=24"
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "4.1.2", # Risk Management for External Exposure
        "statement-ids": [
            "1", # Ensure risks from external exposure of services like SSH are identified and mitigated.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/RiskManagement/RiskManagementGuidelines.pdf#page=17"
    },
]

violation[{
  "title": "SSH (port 22) should not be open to the world",
  "description": "Security group allows SSH access (port 22) from 0.0.0.0/0, which poses a security risk.",
}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/0"
  input.IpPermissions[_].ToPort == 22
}
