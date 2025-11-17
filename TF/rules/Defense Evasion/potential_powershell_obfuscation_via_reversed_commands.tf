resource "azurerm_sentinel_alert_rule_scheduled" "potential_powershell_obfuscation_via_reversed_commands" {
  name                       = "potential_powershell_obfuscation_via_reversed_commands"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential PowerShell Obfuscation Via Reversed Commands"
  description                = "Detects the presence of reversed PowerShell commands in the CommandLine. This is often used as a method of obfuscation by attackers - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "hctac" or ProcessCommandLine contains "kaerb" or ProcessCommandLine contains "dnammoc" or ProcessCommandLine contains "ekovn" or ProcessCommandLine contains "eliFd" or ProcessCommandLine contains "rahc" or ProcessCommandLine contains "etirw" or ProcessCommandLine contains "golon" or ProcessCommandLine contains "tninon" or ProcessCommandLine contains "eddih" or ProcessCommandLine contains "tpircS" or ProcessCommandLine contains "ssecorp" or ProcessCommandLine contains "llehsrewop" or ProcessCommandLine contains "esnopser" or ProcessCommandLine contains "daolnwod" or ProcessCommandLine contains "tneilCbeW" or ProcessCommandLine contains "tneilc" or ProcessCommandLine contains "ptth" or ProcessCommandLine contains "elifotevas" or ProcessCommandLine contains "46esab" or ProcessCommandLine contains "htaPpmeTteG" or ProcessCommandLine contains "tcejbO" or ProcessCommandLine contains "maerts" or ProcessCommandLine contains "hcaerof" or ProcessCommandLine contains "retupmoc") and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll")))) and (not((ProcessCommandLine contains " -EncodedCommand " or ProcessCommandLine contains " -enc ")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1027", "T1059"]
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