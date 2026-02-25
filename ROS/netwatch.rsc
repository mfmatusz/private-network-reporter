# Netwatch example - monitor specific host and trigger scan on state change
# Replace 192.168.88.200 with actual IP to monitor
/tool netwatch add host=192.168.88.200 interval=2m \
  up-script=":delay 30s; :global PnrEventIp 192.168.88.200; /system script run pnr-event-on-discover" \
  down-script=""