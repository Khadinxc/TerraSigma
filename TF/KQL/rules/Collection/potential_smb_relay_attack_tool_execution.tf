resource "azurerm_sentinel_alert_rule_scheduled" "potential_smb_relay_attack_tool_execution" {
  name                       = "potential_smb_relay_attack_tool_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential SMB Relay Attack Tool Execution"
  description                = "Detects different hacktools used for relay attacks on Windows for privilege escalation - Legitimate files with these rare hacktool names"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains ".exe -c \"{" and ProcessCommandLine endswith "}\" -z") or (FolderPath contains "PetitPotam" or FolderPath contains "RottenPotato" or FolderPath contains "HotPotato" or FolderPath contains "JuicyPotato" or FolderPath contains "\\just_dce_" or FolderPath contains "Juicy Potato" or FolderPath contains "\\temp\\rot.exe" or FolderPath contains "\\Potato.exe" or FolderPath contains "\\SpoolSample.exe" or FolderPath contains "\\Responder.exe" or FolderPath contains "\\smbrelayx" or FolderPath contains "\\ntlmrelayx" or FolderPath contains "\\LocalPotato") or (ProcessCommandLine contains "Invoke-Tater" or ProcessCommandLine contains " smbrelay" or ProcessCommandLine contains " ntlmrelay" or ProcessCommandLine contains "cme smb " or ProcessCommandLine contains " /ntlm:NTLMhash " or ProcessCommandLine contains "Invoke-PetitPotam" or (ProcessCommandLine contains ".exe -t " and ProcessCommandLine contains " -p "))) and (not((FolderPath contains "HotPotatoes6" or FolderPath contains "HotPotatoes7" or FolderPath contains "HotPotatoes ")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection", "Execution", "CredentialAccess"]
  techniques                 = ["T1557"]
  enabled                    = true

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = false
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
      by_entities             = []
      by_alert_details        = []
      by_custom_details       = []
    }
  }

  event_grouping {
    aggregation_method = "SingleAlert"
  }

  entity_mapping {
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}