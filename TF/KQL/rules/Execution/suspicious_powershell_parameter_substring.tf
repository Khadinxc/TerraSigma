resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_powershell_parameter_substring" {
  name                       = "suspicious_powershell_parameter_substring"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious PowerShell Parameter Substring"
  description                = "Detects suspicious PowerShell invocation with a parameter substring"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -windowstyle h " or ProcessCommandLine contains " -windowstyl h" or ProcessCommandLine contains " -windowsty h" or ProcessCommandLine contains " -windowst h" or ProcessCommandLine contains " -windows h" or ProcessCommandLine contains " -windo h" or ProcessCommandLine contains " -wind h" or ProcessCommandLine contains " -win h" or ProcessCommandLine contains " -wi h" or ProcessCommandLine contains " -win h " or ProcessCommandLine contains " -win hi " or ProcessCommandLine contains " -win hid " or ProcessCommandLine contains " -win hidd " or ProcessCommandLine contains " -win hidde " or ProcessCommandLine contains " -NoPr " or ProcessCommandLine contains " -NoPro " or ProcessCommandLine contains " -NoProf " or ProcessCommandLine contains " -NoProfi " or ProcessCommandLine contains " -NoProfil " or ProcessCommandLine contains " -nonin " or ProcessCommandLine contains " -nonint " or ProcessCommandLine contains " -noninte " or ProcessCommandLine contains " -noninter " or ProcessCommandLine contains " -nonintera " or ProcessCommandLine contains " -noninterac " or ProcessCommandLine contains " -noninteract " or ProcessCommandLine contains " -noninteracti " or ProcessCommandLine contains " -noninteractiv " or ProcessCommandLine contains " -ec " or ProcessCommandLine contains " -encodedComman " or ProcessCommandLine contains " -encodedComma " or ProcessCommandLine contains " -encodedComm " or ProcessCommandLine contains " -encodedCom " or ProcessCommandLine contains " -encodedCo " or ProcessCommandLine contains " -encodedC " or ProcessCommandLine contains " -encoded " or ProcessCommandLine contains " -encode " or ProcessCommandLine contains " -encod " or ProcessCommandLine contains " -enco " or ProcessCommandLine contains " -en " or ProcessCommandLine contains " -executionpolic " or ProcessCommandLine contains " -executionpoli " or ProcessCommandLine contains " -executionpol " or ProcessCommandLine contains " -executionpo " or ProcessCommandLine contains " -executionp " or ProcessCommandLine contains " -execution bypass" or ProcessCommandLine contains " -executio bypass" or ProcessCommandLine contains " -executi bypass" or ProcessCommandLine contains " -execut bypass" or ProcessCommandLine contains " -execu bypass" or ProcessCommandLine contains " -exec bypass" or ProcessCommandLine contains " -exe bypass" or ProcessCommandLine contains " -ex bypass" or ProcessCommandLine contains " -ep bypass" or ProcessCommandLine contains " /windowstyle h " or ProcessCommandLine contains " /windowstyl h" or ProcessCommandLine contains " /windowsty h" or ProcessCommandLine contains " /windowst h" or ProcessCommandLine contains " /windows h" or ProcessCommandLine contains " /windo h" or ProcessCommandLine contains " /wind h" or ProcessCommandLine contains " /win h" or ProcessCommandLine contains " /wi h" or ProcessCommandLine contains " /win h " or ProcessCommandLine contains " /win hi " or ProcessCommandLine contains " /win hid " or ProcessCommandLine contains " /win hidd " or ProcessCommandLine contains " /win hidde " or ProcessCommandLine contains " /NoPr " or ProcessCommandLine contains " /NoPro " or ProcessCommandLine contains " /NoProf " or ProcessCommandLine contains " /NoProfi " or ProcessCommandLine contains " /NoProfil " or ProcessCommandLine contains " /nonin " or ProcessCommandLine contains " /nonint " or ProcessCommandLine contains " /noninte " or ProcessCommandLine contains " /noninter " or ProcessCommandLine contains " /nonintera " or ProcessCommandLine contains " /noninterac " or ProcessCommandLine contains " /noninteract " or ProcessCommandLine contains " /noninteracti " or ProcessCommandLine contains " /noninteractiv " or ProcessCommandLine contains " /ec " or ProcessCommandLine contains " /encodedComman " or ProcessCommandLine contains " /encodedComma " or ProcessCommandLine contains " /encodedComm " or ProcessCommandLine contains " /encodedCom " or ProcessCommandLine contains " /encodedCo " or ProcessCommandLine contains " /encodedC " or ProcessCommandLine contains " /encoded " or ProcessCommandLine contains " /encode " or ProcessCommandLine contains " /encod " or ProcessCommandLine contains " /enco " or ProcessCommandLine contains " /en " or ProcessCommandLine contains " /executionpolic " or ProcessCommandLine contains " /executionpoli " or ProcessCommandLine contains " /executionpol " or ProcessCommandLine contains " /executionpo " or ProcessCommandLine contains " /executionp " or ProcessCommandLine contains " /execution bypass" or ProcessCommandLine contains " /executio bypass" or ProcessCommandLine contains " /executi bypass" or ProcessCommandLine contains " /execut bypass" or ProcessCommandLine contains " /execu bypass" or ProcessCommandLine contains " /exec bypass" or ProcessCommandLine contains " /exe bypass" or ProcessCommandLine contains " /ex bypass" or ProcessCommandLine contains " /ep bypass") and (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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