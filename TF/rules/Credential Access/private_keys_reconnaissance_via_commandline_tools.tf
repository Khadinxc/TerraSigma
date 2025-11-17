resource "azurerm_sentinel_alert_rule_scheduled" "private_keys_reconnaissance_via_commandline_tools" {
  name                       = "private_keys_reconnaissance_via_commandline_tools"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Private Keys Reconnaissance Via CommandLine Tools"
  description                = "Adversaries may search for private key certificate files on compromised systems for insecurely stored credential"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".key" or ProcessCommandLine contains ".pgp" or ProcessCommandLine contains ".gpg" or ProcessCommandLine contains ".ppk" or ProcessCommandLine contains ".p12" or ProcessCommandLine contains ".pem" or ProcessCommandLine contains ".pfx" or ProcessCommandLine contains ".cer" or ProcessCommandLine contains ".p7b" or ProcessCommandLine contains ".asc") and ((ProcessCommandLine contains "dir " and (FolderPath endswith "\\cmd.exe" or ProcessVersionInfoOriginalFileName =~ "Cmd.Exe")) or (ProcessCommandLine contains "Get-ChildItem " and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll")))) or (FolderPath endswith "\\findstr.exe" or ProcessVersionInfoOriginalFileName =~ "FINDSTR.EXE"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1552"]
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