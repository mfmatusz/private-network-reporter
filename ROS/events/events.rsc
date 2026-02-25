# ============================
# Private Network Reporter (PNR) - RouterOS scripts
# 
# CONFIGURATION: edit values below before import
# After editing: /import file-name=events.rsc
# ============================

# -------------------------------------------
# 1) pnr-event-on-discover
#    Send single event (e.g. from Netwatch / DHCP hook)
#    Usage: :global PnrEventIp "192.168.88.2"; /system script run pnr-event-on-discover
# -------------------------------------------
:if ([:len [/system script find name="pnr-event-on-discover"]] > 0) do={
  /system script remove [find name="pnr-event-on-discover"]
}
:local SrcPnrEvent ("
:global PnrEventIp;

# === CONFIG (edit before import) ===
:local pnrHost "<your-pnr-host-ip>"
:local pnrPort "8080"
:local pnrSecret "<your-event-secret-base64-32-bytes>"
# ===================================

:if ([:len \$PnrEventIp] = 0) do={ 
  :log warning \"pnr-event-on-discover: missing IP param\"; 
  :return 
}

:local ip \$PnrEventIp
:local url (\"https://\" . \$pnrHost . \":\" . \$pnrPort . \"/events\")

# Get MAC from ARP table, use empty string if not found
:local mac \"\"
:do {
  :set mac [/ip arp get [find where address=\$ip] mac-address]
} on-error={ :set mac \"\" }

# Build JSON payload
:local body (\"{\\\"ip\\\":\\\"\" . \$ip . \"\\\",\\\"mac\\\":\\\"\" . \$mac . \"\\\",\\\"source\\\":\\\"routeros\\\"}\")
:local timestamp [:tostr [:timestamp]]
:local data (\$body . \$pnrSecret . \$timestamp)
:local sig [:convert \$data to=hex transform=sha512]

# Send with SHA512 signature and timestamp
:do {
  /tool fetch mode=https url=\$url http-method=post http-data=\$body keep-result=no \\
    http-header-field=(\"Content-Type:application/json,X-Auth-Signature:\" . \$sig . \",X-Auth-Timestamp:\" . \$timestamp)
  :log info (\"pnr-event-on-discover: sent ip=\" . \$ip . \", sig=\" . [:pick \$sig 0 16] . \"...\")
} on-error={ :log error (\"pnr-event-on-discover: failed to send ip=\" . \$ip) }

# Clear global variable
:set PnrEventIp
")
/system script add name="pnr-event-on-discover" policy=read,write,test source=$SrcPnrEvent

# -------------------------------------------
# 2) send-arp-batch
#    Send JSON batch [{ip,mac},...]
#    Requires global variable PnrBatchData
# -------------------------------------------
:if ([:len [/system script find name="send-arp-batch"]] > 0) do={
  /system script remove [find name="send-arp-batch"]
}
:local SrcSendArpBatch ("
:global PnrBatchData;

# === CONFIG (edit before import) ===
:local pnrHost "<your-pnr-host-ip>"
:local pnrPort "8080"
:local pnrSecret "<your-event-secret-base64-32-bytes>"
# ===================================

:if ([:len \$PnrBatchData] = 0) do={ 
  :log warning \"send-arp-batch: empty entries\"; 
  :return 
}

:local entries \$PnrBatchData
:local url (\"https://\" . \$pnrHost . \":\" . \$pnrPort . \"/arp/harvest\")
:local timestamp [:tostr [:timestamp]]
:local data (\$entries . \$pnrSecret . \$timestamp)
:local sig [:convert \$data to=hex transform=sha512]

:do {
  /tool fetch mode=https url=\$url http-method=post http-data=\$entries keep-result=no \\
    http-header-field=(\"Content-Type:application/json,X-Auth-Signature:\" . \$sig . \",X-Auth-Timestamp:\" . \$timestamp)
  :log info (\"send-arp-batch: sent batch size=\" . [:len \$entries] . \", sig=\" . [:pick \$sig 0 16] . \"...\")
} on-error={ :log error \"send-arp-batch: failed to send batch\"}

# Clear global variable
:set PnrBatchData
")
/system script add name="send-arp-batch" policy=read,write,test source=$SrcSendArpBatch

# -------------------------------------------
# 3) arp-ingest-batcher
#    Builds JSON batch from ARP table and sends in chunks (~4kB or max 80 entries)
# -------------------------------------------
:if ([:len [/system script find name="arp-ingest-batcher"]] > 0) do={
  /system script remove [find name="arp-ingest-batcher"]
}
:local SrcBatcher ("
:local ids [/ip arp find where complete=yes]
:local buf \"[\"; :local count 0; :local sent 0; :local first true
:local totalEntries [:len \$ids]

:log info (\"arp-ingest-batcher: processing \$totalEntries ARP entries\")

:foreach i in=\$ids do={
  :local ip [/ip arp get \$i address]
  :local mac [/ip arp get \$i mac-address]
  
  # Skip invalid entries
  :if (!(\$ip=\"0.0.0.0\" || \$mac=\"00:00:00:00:00:00\" || [:len \$ip]=0 || [:len \$mac]=0)) do={
    # Build JSON item
    :local item (\"{\\\"ip\\\":\\\"\" . \$ip . \"\\\",\\\"mac\\\":\\\"\" . \$mac . \"\\\"}\")
    :if (\$first) do={ :set first false } else={ :set buf (\$buf . \",\") }
    :set buf (\$buf . \$item)
    :set count (\$count + 1)

    # Send batch when size or count limit exceeded
    :if (([:len \$buf] > 4000) || (\$count >= 80)) do={
      :set buf (\$buf . \"]\")
      :global PnrBatchData \$buf
      /system script run send-arp-batch
      :set sent (\$sent + \$count)
      :set buf \"[\"; :set count 0; :set first true
      :delay 500ms
    }
  }
}

# Send remaining entries
:if (\$count > 0) do={
  :set buf (\$buf . \"]\")
  :global PnrBatchData \$buf
  /system script run send-arp-batch
  :set sent (\$sent + \$count)
}

:log info (\"arp-ingest-batcher: completed, sent=\" . \$sent . \" entries\")
")
/system script add name="arp-ingest-batcher" policy=read,write,test source=$SrcBatcher
