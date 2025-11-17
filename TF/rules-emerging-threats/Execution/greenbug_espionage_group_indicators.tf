resource "azurerm_sentinel_alert_rule_scheduled" "greenbug_espionage_group_indicators" {
  name                       = "greenbug_espionage_group_indicators"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Greenbug Espionage Group Indicators"
  description                = "Detects tools and process executions used by Greenbug in their May 2020 campaign as reported by Symantec - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith ":\\ProgramData\\adobe\\Adobe.exe" or FolderPath endswith ":\\ProgramData\\oracle\\local.exe" or FolderPath endswith "\\revshell.exe" or FolderPath endswith "\\infopagesbackup\\ncat.exe" or FolderPath endswith ":\\ProgramData\\comms\\comms.exe") or (ProcessCommandLine contains "-ExecutionPolicy Bypass -File" and ProcessCommandLine contains "\\msf.ps1") or (ProcessCommandLine contains "infopagesbackup" and ProcessCommandLine contains "\\ncat" and ProcessCommandLine contains "-e cmd.exe") or ProcessCommandLine contains "L3NlcnZlcj1" or (ProcessCommandLine contains "system.Data.SqlClient.SqlDataAdapter($cmd); [void]$da.fill" or ProcessCommandLine contains "-nop -w hidden -c $k=new-object" or ProcessCommandLine contains "[Net.CredentialCache]::DefaultCredentials;IEX " or ProcessCommandLine contains " -nop -w hidden -c $m=new-object net.webclient;$m" or ProcessCommandLine contains "-noninteractive -executionpolicy bypass whoami" or ProcessCommandLine contains "-noninteractive -executionpolicy bypass netstat -a")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "CommandAndControl", "DefenseEvasion"]
  techniques                 = ["T1059", "T1105", "T1036"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}