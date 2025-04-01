package compliance_framework.template.aws._deny_open_rdp

# METADATA
# title: RDP (port 3389) should not be open to the world
# description: Verifies that RDP port 3389 is not publicly accessible to reduce the attack surface.
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
            "5", # Ensure that services like RDP are not exposed to the public network unnecessarily.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/CyberSecurity/Cyber%20Security%20Framework.pdf#page=38"
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "2.2.4", # Access Control
        "statement-ids": [
            "1", # Ensure that only authorized IP ranges can access services like RDP.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/ITGovernance/ITGovernanceFramework.pdf#page=36"
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "3.1.1", # Secure Network Design
        "statement-ids": [
            "3", # Ensure services that are not needed externally (such as RDP) are isolated from the internet.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/CloudComputing/CloudComputingFramework.pdf#page=24"
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "4.1.2", # Risk Management for External Exposure
        "statement-ids": [
            "1", # Ensure risks from external exposure of services like RDP are identified and mitigated.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/RiskManagement/RiskManagementGuidelines.pdf#page=17"
    },
]

violation[{
  "title": "RDP (port 3389) should not be open to the world",
  "description": "Security group allows unrestricted RDP access, which increases the attack surface.",
}] if {
  input.IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/0"
  input.IpPermissions[_].ToPort == 3389
}