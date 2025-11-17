resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_process_by_web_server_process" {
  name                       = "suspicious_process_by_web_server_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Process By Web Server Process"
  description                = "Detects potentially suspicious processes being spawned by a web server process which could be the result of a successfully placed web shell or exploitation - Particular web applications may spawn a shell process legitimately"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((InitiatingProcessFolderPath contains "-tomcat-" or InitiatingProcessFolderPath contains "\\tomcat") and (InitiatingProcessFolderPath endswith "\\java.exe" or InitiatingProcessFolderPath endswith "\\javaw.exe")) or ((InitiatingProcessCommandLine contains "CATALINA_HOME" or InitiatingProcessCommandLine contains "catalina.home" or InitiatingProcessCommandLine contains "catalina.jar") and (InitiatingProcessFolderPath endswith "\\java.exe" or InitiatingProcessFolderPath endswith "\\javaw.exe")) or (InitiatingProcessFolderPath endswith "\\caddy.exe" or InitiatingProcessFolderPath endswith "\\httpd.exe" or InitiatingProcessFolderPath endswith "\\nginx.exe" or InitiatingProcessFolderPath endswith "\\php-cgi.exe" or InitiatingProcessFolderPath endswith "\\php.exe" or InitiatingProcessFolderPath endswith "\\tomcat.exe" or InitiatingProcessFolderPath endswith "\\UMWorkerProcess.exe" or InitiatingProcessFolderPath endswith "\\w3wp.exe" or InitiatingProcessFolderPath endswith "\\ws_TomcatService.exe")) and (FolderPath endswith "\\arp.exe" or FolderPath endswith "\\at.exe" or FolderPath endswith "\\bash.exe" or FolderPath endswith "\\bitsadmin.exe" or FolderPath endswith "\\certutil.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\dsget.exe" or FolderPath endswith "\\hostname.exe" or FolderPath endswith "\\nbtstat.exe" or FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe" or FolderPath endswith "\\netdom.exe" or FolderPath endswith "\\netsh.exe" or FolderPath endswith "\\nltest.exe" or FolderPath endswith "\\ntdsutil.exe" or FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\qprocess.exe" or FolderPath endswith "\\query.exe" or FolderPath endswith "\\qwinsta.exe" or FolderPath endswith "\\reg.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\sc.exe" or FolderPath endswith "\\sh.exe" or FolderPath endswith "\\wmic.exe" or FolderPath endswith "\\wscript.exe" or FolderPath endswith "\\wusa.exe") and (not(((ProcessCommandLine endswith "Windows\\system32\\cmd.exe /c C:\\ManageEngine\\ADManager \"Plus\\ES\\bin\\elasticsearch.bat -Enode.name=RMP-NODE1 -pelasticsearch-pid.txt" and InitiatingProcessFolderPath endswith "\\java.exe") or ((ProcessCommandLine contains "sc query" and ProcessCommandLine contains "ADManager Plus") and InitiatingProcessFolderPath endswith "\\java.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "InitialAccess"]
  techniques                 = ["T1505", "T1190"]
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