resource "azurerm_sentinel_alert_rule_scheduled" "pua_potential_pe_metadata_tamper_using_rcedit" {
  name                       = "pua_potential_pe_metadata_tamper_using_rcedit"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Potential PE Metadata Tamper Using Rcedit"
  description                = "Detects the use of rcedit to potentially alter executable PE metadata properties, which could conceal efforts to rename system utilities for defense evasion. - Legitimate use of the tool by administrators or users to update metadata of a binary"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "OriginalFileName" or ProcessCommandLine contains "CompanyName" or ProcessCommandLine contains "FileDescription" or ProcessCommandLine contains "ProductName" or ProcessCommandLine contains "ProductVersion" or ProcessCommandLine contains "LegalCopyright") and ProcessCommandLine contains "--set-" and ((FolderPath endswith "\\rcedit-x64.exe" or FolderPath endswith "\\rcedit-x86.exe") or ProcessVersionInfoFileDescription =~ "Edit resources of exe" or ProcessVersionInfoProductName =~ "rcedit")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036", "T1027"]
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