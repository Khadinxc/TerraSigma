resource "azurerm_sentinel_alert_rule_scheduled" "linux_hacktool_execution" {
  name                       = "linux_hacktool_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Linux HackTool Execution"
  description                = "Detects known hacktool execution based on image name. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath contains "/cobaltstrike" or FolderPath contains "/teamserver") or (FolderPath endswith "/crackmapexec" or FolderPath endswith "/havoc" or FolderPath endswith "/merlin-agent" or FolderPath endswith "/merlinServer-Linux-x64" or FolderPath endswith "/msfconsole" or FolderPath endswith "/msfvenom" or FolderPath endswith "/ps-empire server" or FolderPath endswith "/ps-empire" or FolderPath endswith "/sliver-client" or FolderPath endswith "/sliver-server" or FolderPath endswith "/Villain.py") or (FolderPath endswith "/aircrack-ng" or FolderPath endswith "/bloodhound-python" or FolderPath endswith "/bpfdos" or FolderPath endswith "/ebpfki" or FolderPath endswith "/evil-winrm" or FolderPath endswith "/hashcat" or FolderPath endswith "/hoaxshell.py" or FolderPath endswith "/hydra" or FolderPath endswith "/john" or FolderPath endswith "/ncrack" or FolderPath endswith "/nxc-ubuntu-latest" or FolderPath endswith "/pidhide" or FolderPath endswith "/pspy32" or FolderPath endswith "/pspy32s" or FolderPath endswith "/pspy64" or FolderPath endswith "/pspy64s" or FolderPath endswith "/setoolkit" or FolderPath endswith "/sqlmap" or FolderPath endswith "/writeblocker") or FolderPath contains "/linpeas" or (FolderPath endswith "/autorecon" or FolderPath endswith "/httpx" or FolderPath endswith "/legion" or FolderPath endswith "/naabu" or FolderPath endswith "/netdiscover" or FolderPath endswith "/nuclei" or FolderPath endswith "/recon-ng") or FolderPath contains "/sniper" or (FolderPath endswith "/dirb" or FolderPath endswith "/dirbuster" or FolderPath endswith "/eyewitness" or FolderPath endswith "/feroxbuster" or FolderPath endswith "/ffuf" or FolderPath endswith "/gobuster" or FolderPath endswith "/wfuzz" or FolderPath endswith "/whatweb") or (FolderPath endswith "/joomscan" or FolderPath endswith "/nikto" or FolderPath endswith "/wpscan")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "ResourceDevelopment"]
  techniques                 = ["T1587"]
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}