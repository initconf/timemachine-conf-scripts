# timemachine-conf-scripts

Bro policy to estimate/measure cutoff bytes for tm.conf thresholds + extract-tm.sh script which searches pcaps if a bro log is supplied to it

The right timemachine to run is :
git.bro.org/time-machine with naokieto branch - its fantastic.

1) for tm-stats.bro (output is still not too elegant but less -S does the trick).

@load tm-stats.bro

Every hour you should see stats for various buckets including estimates on coverage per cutoff threshold.

you can add remove cuttoffs by adding following to your site.bro

redef cutoff_bytes += { ["CUT_32K"] = 32000, } ;

2) for extract-tm.sh

useage:

grep <sender> smtp.log  > sender.smtp.log

Example: 
extract-tm.sh sender.smtp.log smtp

likewise:

extract-tm.sh sender.dns.log dns

Basically, 

extract-tm.sh <your-extracted-bro-log> <bucket-name>

You shuld see extracted data in /tmp/

For extract-tm.sh:

configure DATA_MOUNTS with the path to your tm pcaps, for example: 

DATA_MOUNTS="/TM/ /TM-SMTP/" 



Sample output:

1438682905.593857 TM_stats::SMTP 70531 29.85 GB        64K=65586(0.930)/142.56 MB(0.005)       25M=70486(0.999)/10.18 GB(0.341)       
1438682905.593857 TM_stats::HTTPS 1059243 375.37 GB        64K=1011009(0.954)/2.12 GB(0.006)       25M=1057384(0.998)/76.40 GB(0.204)       
1438682905.593857 TM_stats::REST 2058065 3.80 TB        64K=2019137(0.981)/560.50 MB(0.000)       25M=2056289(0.999)/113.05 GB(0.029)      
1438682905.593857 TM_stats::ICMP 727299 19.35 GB        64K=722659(0.994)/88.55 MB(0.004)       25M=727116(1.000)/10.54 GB(0.545)       
1438682905.593857 TM_stats::UDP 1090104 2.84 GB        64K=1088015(0.998)/294.84 MB(0.101)       25M=1090091(1.000)/1.29 GB(0.452)     
1438686419.293957 TM_stats::DNS 1264432 58.79 MB        64K=1264379(1.000)/54.15 MB(0.921)       25M=1264432(1.000)/58.79 MB(1.000)   
1438686419.293957 TM_stats::HTTP 1157028 314.75 GB        64K=1104311(0.954)/1.95 GB(0.006)       25M=1155869(0.999)/60.15 GB(0.191) 
1438686419.293957 TM_stats::SSH 237433 301.65 GB        64K=235764(0.993)/51.52 MB(0.000)       25M=237125(0.999)/2.03 GB(0.007)    

