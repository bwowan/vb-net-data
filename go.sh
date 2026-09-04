sudo setcap 'cap_net_raw,cap_net_admin+ep' /mnt/DevData/Job/NetData/net_listener/target/debug/net_listener

sudo setcap cap_net_raw,cap_net_admin=eip target/debug/net_listener
getcap
sudo setcap 'cap_net_raw,cap_net_admin=eip'

sudo lldb-server platform --listen "*:1234" --server

