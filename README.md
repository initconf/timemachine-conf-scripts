# timemachine-conf-scripts
Bro policy to estimate/measure cutoff bytes for tm.conf thresholds + extract-tm.sh script which searches pcaps if a bro log is supplied to it


for extract-tm.sh:

configure DATA_MOUNTS with the path to your tm pcaps, for example: 

DATA_MOUNTS="/TM/ /TM-SMTP/" 


For tm-stats.bro:

you can add remove cuttoffs by adding following to your site.bro

redef cutoff_bytes += { ["CUT_32K"] = 32000, } ;


Sample output:

1438682905.593857 TM_stats::SMTP 70531 29.85 GB        64K=65586(0.930)/142.56 MB(0.005)       25M=70486(0.999)/10.18 GB(0.341)       10K=55181(0.782)/2.44 MB(0.000)       32K=64216(0.910)/82.02 MB(
1438682905.593857 TM_stats::HTTPS 1059243 375.37 GB        64K=1011009(0.954)/2.12 GB(0.006)       25M=1057384(0.998)/76.40 GB(0.204)       10K=762697(0.720)/87.74 MB(0.000)       32K=994697(0.939)/
1438682905.593857 TM_stats::REST 2058065 3.80 TB        64K=2019137(0.981)/560.50 MB(0.000)       25M=2056289(0.999)/113.05 GB(0.029)       10K=1944769(0.945)/35.47 MB(0.000)       32K=2015035(0.979
1438682905.593857 TM_stats::ICMP 727299 19.35 GB        64K=722659(0.994)/88.55 MB(0.004)       25M=727116(1.000)/10.54 GB(0.545)       10K=717491(0.987)/13.75 MB(0.001)       32K=721687(0.992)/44.0
1438682905.593857 TM_stats::UDP 1090104 2.84 GB        64K=1088015(0.998)/294.84 MB(0.101)       25M=1090091(1.000)/1.29 GB(0.452)       10K=1044486(0.958)/77.44 MB(0.027)       32K=1086691(0.997)/2
1438686419.293957 TM_stats::DNS 1264432 58.79 MB        64K=1264379(1.000)/54.15 MB(0.921)       25M=1264432(1.000)/58.79 MB(1.000)       10K=1260141(0.997)/45.47 MB(0.773)       32K=1264346(1.000)/
1438686419.293957 TM_stats::HTTP 1157028 314.75 GB        64K=1104311(0.954)/1.95 GB(0.006)       25M=1155869(0.999)/60.15 GB(0.191)       10K=903541(0.781)/70.67 MB(0.000)       32K=1086691(0.939)/
1438686419.293957 TM_stats::SSH 237433 301.65 GB        64K=235764(0.993)/51.52 MB(0.000)       25M=237125(0.999)/2.03 GB(0.007)       10K=228668(0.963)/3.36 MB(0.000)       32K=235376(0.991)/33.49

