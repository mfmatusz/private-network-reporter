/ip dhcp-server set 0 lease-script=":if (\$leaseBound = 1) do={ :delay 30s; :global PnrEventIp \$leaseActIP; /system script run pnr-event-on-discover }"
