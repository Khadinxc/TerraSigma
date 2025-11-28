resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_velociraptor_child_process" {
  name                       = "suspicious_velociraptor_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Velociraptor Child Process"
  description                = "Detects the suspicious use of the Velociraptor DFIR tool to execute other tools or download additional payloads, as seen in a campaign where it was abused for remote access and to stage further attacks. - Legitimate administrators or incident responders might use Velociraptor to execute scripts or tools. However, the combination of Velociraptor spawning these specific processes with these command lines is suspicious. Tuning may be required to exclude known administrative actions or specific scripts."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\Velociraptor.exe" and ((ProcessCommandLine contains "msiexec" and ProcessCommandLine contains "/i" and ProcessCommandLine contains "http") or ((ProcessCommandLine contains "Invoke-WebRequest " or ProcessCommandLine contains "IWR " or ProcessCommandLine contains ".DownloadFile" or ProcessCommandLine contains ".DownloadString") and (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\pwsh.exe")) or (ProcessCommandLine contains "code.exe" and ProcessCommandLine contains "tunnel" and ProcessCommandLine contains "--accept-server-license-terms"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl", "Persistence", "DefenseEvasion"]
  techniques                 = ["T1219"]
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