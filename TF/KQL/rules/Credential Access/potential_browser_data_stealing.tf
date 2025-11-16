resource "azurerm_sentinel_alert_rule_scheduled" "potential_browser_data_stealing" {
  name                       = "potential_browser_data_stealing"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Browser Data Stealing"
  description                = "Adversaries may acquire credentials from web browsers by reading files specific to the target browser. Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. Web browsers typically store the credentials in an encrypted format within a credential store."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "copy-item" or ProcessCommandLine contains "copy " or ProcessCommandLine contains "cpi " or ProcessCommandLine contains " cp " or ProcessCommandLine contains "move " or ProcessCommandLine contains "move-item" or ProcessCommandLine contains " mi " or ProcessCommandLine contains " mv ") or (FolderPath endswith "\\esentutl.exe" or FolderPath endswith "\\xcopy.exe" or FolderPath endswith "\\robocopy.exe") or (ProcessVersionInfoOriginalFileName in~ ("esentutl.exe", "XCOPY.EXE", "robocopy.exe"))) and (ProcessCommandLine contains "\\Amigo\\User Data" or ProcessCommandLine contains "\\BraveSoftware\\Brave-Browser\\User Data" or ProcessCommandLine contains "\\CentBrowser\\User Data" or ProcessCommandLine contains "\\Chromium\\User Data" or ProcessCommandLine contains "\\CocCoc\\Browser\\User Data" or ProcessCommandLine contains "\\Comodo\\Dragon\\User Data" or ProcessCommandLine contains "\\Elements Browser\\User Data" or ProcessCommandLine contains "\\Epic Privacy Browser\\User Data" or ProcessCommandLine contains "\\Google\\Chrome Beta\\User Data" or ProcessCommandLine contains "\\Google\\Chrome SxS\\User Data" or ProcessCommandLine contains "\\Google\\Chrome\\User Data\\" or ProcessCommandLine contains "\\Kometa\\User Data" or ProcessCommandLine contains "\\Maxthon5\\Users" or ProcessCommandLine contains "\\Microsoft\\Edge\\User Data" or ProcessCommandLine contains "\\Mozilla\\Firefox\\Profiles" or ProcessCommandLine contains "\\Nichrome\\User Data" or ProcessCommandLine contains "\\Opera Software\\Opera GX Stable\\" or ProcessCommandLine contains "\\Opera Software\\Opera Neon\\User Data" or ProcessCommandLine contains "\\Opera Software\\Opera Stable\\" or ProcessCommandLine contains "\\Orbitum\\User Data" or ProcessCommandLine contains "\\QIP Surf\\User Data" or ProcessCommandLine contains "\\Sputnik\\User Data" or ProcessCommandLine contains "\\Torch\\User Data" or ProcessCommandLine contains "\\uCozMedia\\Uran\\User Data" or ProcessCommandLine contains "\\Vivaldi\\User Data")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1555"]
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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