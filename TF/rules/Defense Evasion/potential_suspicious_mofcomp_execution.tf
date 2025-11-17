resource "azurerm_sentinel_alert_rule_scheduled" "potential_suspicious_mofcomp_execution" {
  name                       = "potential_suspicious_mofcomp_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Suspicious Mofcomp Execution"
  description                = "Detects execution of the \"mofcomp\" utility as a child of a suspicious shell or script running utility or by having a suspicious path in the commandline. The \"mofcomp\" utility parses a file containing MOF statements and adds the classes and class instances defined in the file to the WMI repository. Attackers abuse this utility to install malicious MOF scripts"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((InitiatingProcessFolderPath endswith "\\cmd.exe" or InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe" or InitiatingProcessFolderPath endswith "\\wsl.exe" or InitiatingProcessFolderPath endswith "\\wscript.exe" or InitiatingProcessFolderPath endswith "\\cscript.exe") or (ProcessCommandLine contains "\\AppData\\Local\\Temp" or ProcessCommandLine contains "\\Users\\Public\\" or ProcessCommandLine contains "\\WINDOWS\\Temp\\" or ProcessCommandLine contains "%temp%" or ProcessCommandLine contains "%tmp%" or ProcessCommandLine contains "%appdata%")) and (FolderPath endswith "\\mofcomp.exe" or ProcessVersionInfoOriginalFileName =~ "mofcomp.exe")) and (not((ProcessCommandLine contains "C:\\Windows\\TEMP\\" and ProcessCommandLine endswith ".mof" and InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"))) and (not((ProcessCommandLine contains "C:\\Windows\\TEMP\\" and ProcessCommandLine endswith ".mof")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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