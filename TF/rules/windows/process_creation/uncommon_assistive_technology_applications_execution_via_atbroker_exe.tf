resource "azurerm_sentinel_alert_rule_scheduled" "uncommon_assistive_technology_applications_execution_via_atbroker_exe" {
  name                       = "uncommon_assistive_technology_applications_execution_via_atbroker_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon  Assistive Technology Applications Execution Via AtBroker.EXE"
  description                = "Detects the start of a non built-in assistive technology applications via \"Atbroker.EXE\". - Legitimate, non-default assistive technology applications execution"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "start" and (FolderPath endswith "\\AtBroker.exe" or ProcessVersionInfoOriginalFileName =~ "AtBroker.exe")) and (not((ProcessCommandLine contains "animations" or ProcessCommandLine contains "audiodescription" or ProcessCommandLine contains "caretbrowsing" or ProcessCommandLine contains "caretwidth" or ProcessCommandLine contains "colorfiltering" or ProcessCommandLine contains "cursorindicator" or ProcessCommandLine contains "cursorscheme" or ProcessCommandLine contains "filterkeys" or ProcessCommandLine contains "focusborderheight" or ProcessCommandLine contains "focusborderwidth" or ProcessCommandLine contains "highcontrast" or ProcessCommandLine contains "keyboardcues" or ProcessCommandLine contains "keyboardpref" or ProcessCommandLine contains "livecaptions" or ProcessCommandLine contains "magnifierpane" or ProcessCommandLine contains "messageduration" or ProcessCommandLine contains "minimumhitradius" or ProcessCommandLine contains "mousekeys" or ProcessCommandLine contains "Narrator" or ProcessCommandLine contains "osk" or ProcessCommandLine contains "overlappedcontent" or ProcessCommandLine contains "showsounds" or ProcessCommandLine contains "soundsentry" or ProcessCommandLine contains "speechreco" or ProcessCommandLine contains "stickykeys" or ProcessCommandLine contains "togglekeys" or ProcessCommandLine contains "voiceaccess" or ProcessCommandLine contains "windowarranging" or ProcessCommandLine contains "windowtracking" or ProcessCommandLine contains "windowtrackingtimeout" or ProcessCommandLine contains "windowtrackingzorder"))) and (not(ProcessCommandLine contains "Oracle_JavaAccessBridge"))
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