resource "azurerm_sentinel_alert_rule_scheduled" "devcon_execution_disabling_vmware_vmci_device" {
  name                       = "devcon_execution_disabling_vmware_vmci_device"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Devcon Execution Disabling VMware VMCI Device"
  description                = "Detects execution of devcon.exe with commands that disable the VMware Virtual Machine Communication Interface (VMCI) device. This can be legitimate during VMware Tools troubleshooting or driver conflicts, but may also indicate malware attempting to hijack communication with the hardware via the VMCI device. This has been used to facilitate VMware ESXi vulnerability exploits to escape VMs and execute code on the ESXi host. - Legitimate VMware administration, Tools installation/uninstallation, or troubleshooting driver conflicts. - Automated scripts in virtualized environments for device cleanup."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " disable " and (FolderPath endswith "\\devcon.exe" or ProcessVersionInfoOriginalFileName =~ "DevCon.exe") and (ProcessCommandLine contains "15AD&DEV_0740" or ProcessCommandLine contains "VMWVMCIHOSTDEV")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1543", "T1562"]
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