resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_crackmapexec_powershell_obfuscation" {
  name                       = "hacktool_crackmapexec_powershell_obfuscation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - CrackMapExec PowerShell Obfuscation"
  description                = "The CrachMapExec pentesting framework implements a PowerShell obfuscation with some static strings detected by this rule."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "join" and ProcessCommandLine contains "split") or ProcessCommandLine contains "( $ShellId[1]+$ShellId[13]+'x')" or (ProcessCommandLine contains "( $PSHome[" and ProcessCommandLine contains "]+$PSHOME[" and ProcessCommandLine contains "]+") or ProcessCommandLine contains "( $env:Public[13]+$env:Public[5]+'x')" or (ProcessCommandLine contains "( $env:ComSpec[4," and ProcessCommandLine contains ",25]-Join'')") or ProcessCommandLine contains "[1,3]+'x'-Join'')") and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1059", "T1027"]
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