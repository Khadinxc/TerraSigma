resource "azurerm_sentinel_alert_rule_scheduled" "potential_commandline_obfuscation_using_unicode_characters_from_suspicious_image" {
  name                       = "potential_commandline_obfuscation_using_unicode_characters_from_suspicious_image"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential CommandLine Obfuscation Using Unicode Characters From Suspicious Image"
  description                = "Detects potential commandline obfuscation using unicode characters. Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\wscript.exe") and (ProcessVersionInfoOriginalFileName in~ ("Cmd.EXE", "cscript.exe", "PowerShell.EXE", "PowerShell_ISE.EXE", "pwsh.dll", "wscript.exe"))) and (ProcessCommandLine contains "ˣ" or ProcessCommandLine contains "˪" or ProcessCommandLine contains "ˢ" or ProcessCommandLine contains "∕" or ProcessCommandLine contains "⁄" or ProcessCommandLine contains "―" or ProcessCommandLine contains "—" or ProcessCommandLine contains " " or ProcessCommandLine contains "¯" or ProcessCommandLine contains "®" or ProcessCommandLine contains "¶" or ProcessCommandLine contains "⠀")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1027"]
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}