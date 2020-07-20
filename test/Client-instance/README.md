#usage of DPVS client config script:
script filename: /root/dpvs-cli-files/
                                     dpvs_cli_setup.py
                                     dpvs_cli_run.py
                                     dpvs_snat_cli_setup.py
                                     dpvs_snat_cli_run.py
scripts end with setup are scipts for linux IP config or route define
scripts end with run are scipts to test IP:port service availability
as SNAT client need ping and do not need stress test,just split into two scripts

Usage:
    python dpvs_cli_setup.py ip1,ip2(config ips) 
    python dpvs_cli_run.py vip:vport  1/0(stress test or not)
    python dpvs_snat_cli_setup.py route
    python dpvs_snat_cli_run.py ip:port 

#roback env
python cleanup.py (sh file generated during env setting)
