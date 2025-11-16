resource "azurerm_sentinel_alert_rule_scheduled" "mint_sandstorm_asperafaspex_suspicious_process_execution" {
  name                       = "mint_sandstorm_asperafaspex_suspicious_process_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Mint Sandstorm - AsperaFaspex Suspicious Process Execution"
  description                = "Detects suspicious execution from AsperaFaspex as seen used by Mint Sandstorm - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessFolderPath contains "aspera" and InitiatingProcessFolderPath contains "\\ruby") and ((((ProcessCommandLine contains " echo " or ProcessCommandLine contains "-dumpmode" or ProcessCommandLine contains "-ssh" or ProcessCommandLine contains ".dmp" or ProcessCommandLine contains "add-MpPreference" or ProcessCommandLine contains "adscredentials" or ProcessCommandLine contains "bitsadmin" or ProcessCommandLine contains "certutil" or ProcessCommandLine contains "csvhost.exe" or ProcessCommandLine contains "DownloadFile" or ProcessCommandLine contains "DownloadString" or ProcessCommandLine contains "dsquery" or ProcessCommandLine contains "ekern.exe" or ProcessCommandLine contains "FromBase64String" or ProcessCommandLine contains "iex " or ProcessCommandLine contains "iex(" or ProcessCommandLine contains "Invoke-Expression" or ProcessCommandLine contains "Invoke-WebRequest" or ProcessCommandLine contains "localgroup administrators" or ProcessCommandLine contains "o365accountconfiguration" or ProcessCommandLine contains "samaccountname=" or ProcessCommandLine contains "set-MpPreference" or ProcessCommandLine contains "svhost.exe" or ProcessCommandLine contains "System.IO.Compression" or ProcessCommandLine contains "System.IO.MemoryStream" or ProcessCommandLine contains "usoprivate" or ProcessCommandLine contains "usoshared" or ProcessCommandLine contains "whoami") or (ProcessCommandLine matches regex "[-/–][Ee^]{1,2}[ncodema^]*\\s[A-Za-z0-9+/=]{15,}" or ProcessCommandLine matches regex "net\\s+user" or ProcessCommandLine matches regex "net\\s+group" or ProcessCommandLine matches regex "query\\s+session")) and (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\powershell_ise.exe")) or (ProcessCommandLine contains "lsass" and (ProcessCommandLine contains "procdump" or ProcessCommandLine contains "tasklist" or ProcessCommandLine contains "findstr")) or ((ProcessCommandLine contains "http" and FolderPath endswith "\\curl.exe") or (ProcessCommandLine contains "localgroup Administrators" and ProcessCommandLine contains "/add") or (ProcessCommandLine contains "net" and (ProcessCommandLine contains "user" and ProcessCommandLine contains "/add")) or ((ProcessCommandLine contains "reg add" and ProcessCommandLine contains "DisableAntiSpyware" and ProcessCommandLine contains "\\Microsoft\\Windows Defender") or (ProcessCommandLine contains "reg add" and ProcessCommandLine contains "DisableRestrictedAdmin" and ProcessCommandLine contains "CurrentControlSet\\Control\\Lsa")) or (ProcessCommandLine contains "E:jscript" or ProcessCommandLine contains "e:vbscript") or (ProcessCommandLine contains "vssadmin" and ProcessCommandLine contains "delete" and ProcessCommandLine contains "shadows") or (ProcessCommandLine contains "wbadmin" and ProcessCommandLine contains "delete" and ProcessCommandLine contains "catalog") or (ProcessCommandLine contains "http" and FolderPath endswith "\\wget.exe") or (ProcessCommandLine contains "wmic" and ProcessCommandLine contains "process call create") or (ProcessCommandLine contains "wmic" and ProcessCommandLine contains "delete" and ProcessCommandLine contains "shadowcopy")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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