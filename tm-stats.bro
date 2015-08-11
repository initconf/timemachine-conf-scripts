@load base/protocols/conn 

module TM_stats;

export {
	

	global estimates_log = open_log_file("tm-estimates"); 


### thresholds and mappings 

	global LOG_INTERVAL = 60 mins &redef; 
	global RESET_INTERVAL = 24 hrs &redef; 

	const T_64K = 65536 ;
	const T_500K = 512000 ;
	const T_5M = 5242880 ; 
	const T_25M = 26214400 ;
	
	const	T_ICMP = T_64K ;
	const	T_SSH = T_500K  ; 
	const	T_HTTPS = T_500K ;
	const 	T_UDP = T_5M ; 
	const	T_HTTP = T_5M ; 
	const	T_DNS = T_5M ; 
	const	T_REST = T_5M ; 
	const	T_SMTP = T_25M ; 
	
	const   I_ICMP = "64K" ;
        const   I_SSH = "500K"  ;
        const   I_HTTPS = "500K" ;
        const   I_UDP = "5M" ;
        const   I_HTTP = "5M" ;
        const   I_DNS = "5M" ;
        const   I_REST = "5M" ;
        const   I_SMTP = "25M" ;

	type buckets: enum {
		DNS, 
		HTTP, 
		HTTPS, 
		SSH, 
		UDP, 
		ICMP, 
		SMTP, 
		REST,
	}; 

	type cutoffs: enum {
		A_CUT_64K, 
		A_CUT_500K, 
		A_CUT_5M, 
		A_CUT_25M, 
	} &redef ; 

	
	global cutoff_bytes: table[string] of count =  {
		#["32K"] = 32000,
                ["64K"] = 65536,
                ["500K"] = 512000,
                ["5M"] = 5242880,
                ["25M"] = 26214400,
	} &redef ; 
	
	type threshold: record {
		CUT_64K: count &default=0 ;
		CUT_500K: count &default=0; 
		CUT_5M: count &default=0 ; 
		CUT_25M: count &default=0; 
	} &redef ; 

	type estimates: record {
		num_conn: count &default = 0;
		total_bytes: count &default =0; 
	} ; 
	
	type guesstimates: table[string] of estimates &redef; 


	type stats : record {
		num_conn: count &default=0; 
                gt_cutoff: count &optional &default=0 ; 
                lt_cutoff: count &optional &default=0 ;
                bytes_wire : count &optional &default=0 ;
		est: threshold; 
		estimation: guesstimates ; 
        };
	

	
	global stats_table: table [buckets] of stats &redef ; 


     ### logging setup
     	redef enum Log::ID += {LOG};
	
	type Info: record {
                ts:   time    &log;
                buckets: string &log ;
                bucket_cutoff: string &log ;
                num_conn: count &log ;

                lt_cutoff: count &log   ;
                gt_cutoff: count &log ;
                coverage : string &log ;
                actual_bytes: string &log ;

                estimation: string &log ;
		filler: string &optional &log ; 
                #actual_bytes: count &log ;

        };

	global log_thresholds: event(rec: Info);

} 

event log_thresholds(rec: Info)
{

	#print fmt ("log_thresholds event called %s", rec); 
}


function bytes_to_human(num: double): string
{

        if (num > 0 && num <= 1024)
                return fmt ("%.2f B", num);
        if (num > 1025 && num <= 1048576 )
                return fmt ("%.2f KB", num/1024);
        if (num > 1048577 && num <= 1073741824 )
                return fmt ("%.2f MB", num/1048576 );
        if (num > 1073741824 +1 && num <= 1099511627776 )
                return fmt ("%.2f GB", num/1073741824);
        if (num >  1099511627776 +1 && num <= 1125899906842624 )
                return fmt ("%.2f TB", num/1099511627776);
}


event log_stats (stats: table[buckets] of stats)
{

	local info: Info;
	local head = fmt ("ts                        buckets              num_conn/MB"); 
		
        for (a in stats){
	
                local gb = bytes_to_human(stats[a]$bytes_wire); 

		local st= fmt ("%s", a); 

		if (/DNS/ in st)
			info$bucket_cutoff = I_DNS; 
		if (/SSH/ in st)
			info$bucket_cutoff = I_SSH; 
		if (/HTTP/ in st)
			info$bucket_cutoff = I_HTTP; 
		if (/HTTPS/ in st)
			info$bucket_cutoff = I_HTTPS; 
		if (/ICMP/ in st)
			info$bucket_cutoff = I_ICMP; 
		if (/UDP/ in st)
			info$bucket_cutoff = I_UDP; 
		if (/SMTP/ in st)
			info$bucket_cutoff = I_SMTP; 
		if (/REST/ in st)
			info$bucket_cutoff = I_REST; 
                
                info$ts = network_time(); 
		info$buckets = fmt ("%s", a); 
                info$num_conn = stats[a]$num_conn; 

                info$lt_cutoff = stats[a]$lt_cutoff ; 
                info$gt_cutoff = stats[a]$gt_cutoff ; 
		info$actual_bytes = fmt ("%s", bytes_to_human(stats[a]$bytes_wire ) ); 


		if (stats[a]$num_conn !=0) 
			info$coverage = fmt ("%.3f", (stats[a]$lt_cutoff*1.0/stats[a]$num_conn*1.0)*100) ; 
		else 
			info$coverage = fmt ("%.3f",0.0) ; 

	
		local est = "" ; 		

		local bytes_wire = stats[a]$bytes_wire; 
		local num_conn = info$num_conn ;

		for (b in stats[a]$estimation )
		{
			local per_conn:double = stats[a]$estimation[b]$num_conn*1.0/info$num_conn*1.0 ;
			local per_bytes:double = stats[a]$estimation[b]$total_bytes*1.0/stats[a]$bytes_wire*1.0 ; 

			local _conn= stats[a]$estimation[b]$num_conn ;
			local _bytes= stats[a]$estimation[b]$total_bytes ; 
			
			est += fmt ("%10s=%s(%.3f)/%s(%.3f)",b, _conn, per_conn, bytes_to_human(_bytes), per_bytes); 
		} 

		print estimates_log, fmt("%s %s %s %s %s", info$ts, info$buckets, num_conn, gb, est); 		
		
		info$estimation=est; 

                Log::write(TM_stats::LOG, info);
	} 

	schedule LOG_INTERVAL { log_stats(stats_table)} ;
}


function initialize_stats_table()
{

	local tmp: stats;

	if (DNS !in stats_table){
		local dns_tmp: stats;
                stats_table[DNS]=dns_tmp ;
        }

	if (HTTP !in stats_table){
		local http_tmp: stats;
                stats_table[HTTP]=http_tmp ;
        }

	if (HTTPS !in stats_table){
		local https_tmp: stats;
                stats_table[HTTPS]=https_tmp ;
        }

	if (SSH !in stats_table){
		local ssh_tmp: stats;
                stats_table[SSH]=ssh_tmp ;
        }

	if (UDP !in stats_table){
		local udp_tmp: stats;
                stats_table[UDP]=udp_tmp ;
        }

	if (ICMP !in stats_table){
		local icmp_tmp: stats;
                stats_table[ICMP]=icmp_tmp ;
        }

	if (SMTP !in stats_table){
		local smtp_tmp: stats;
                stats_table[SMTP]=smtp_tmp ;
        }

	if (REST !in stats_table){
		local all_tmp: stats;
                stats_table[REST]=all_tmp ;
        }

}

event init_log_stats()
{

	schedule LOG_INTERVAL { log_stats(stats_table)} ; 
}


event reset_stats()
{



	event log_stats(stats_table);

	##Log::write(TM_stats::LOG, [info$ts,  

	print estimates_log, fmt("%.6f RESETTING STATS", network_time());


	
	for (a in stats_table)
		delete stats_table[a];

	schedule RESET_INTERVAL { reset_stats()} ;
}	

event bro_init() &priority=5
{
	set_buf(estimates_log,F);
	Log::create_stream(TM_stats::LOG, [$columns=Info, $ev=log_thresholds]);
	
	initialize_stats_table(); 

	if ("10K" !in cutoff_bytes)
		cutoff_bytes["10K"] = 1024; 

	schedule 1 sec { init_log_stats()} ; 
	
	schedule RESET_INTERVAL { reset_stats()} ;

} 


function increment_bucket_cutoff(s_buck: buckets, c_off: string , bytes: count)
{

	#print fmt ("%s - %s", s_buck, c_off); 

	if (s_buck !in stats_table)
	{ 	local tmp: stats ; 
		stats_table[s_buck] = tmp; 
	} 
	if (c_off !in stats_table[s_buck]$estimation) 
	{
		local a_tmp : estimates ; 
		stats_table[s_buck]$estimation[c_off]=a_tmp; 
	}

	stats_table[s_buck]$estimation[c_off]$num_conn  += 1; 
	stats_table[s_buck]$estimation[c_off]$total_bytes += bytes ; 
	#print fmt ("%s" , stats_table); 

	#stats_table[SSH]$estimation[s_buck][c_off] ;
} 

function populate_buckets_stats(s_buck: buckets, bytes: count, T_var: count)
{

	if (s_buck !in stats_table)
	{
		local _tmp: stats;
                stats_table[s_buck]=_tmp ;
	} 

	TM_stats::stats_table[s_buck]$num_conn += 1;
	TM_stats::stats_table[s_buck]$bytes_wire += bytes;

	
	if (bytes >= T_var)
       		TM_stats::stats_table[s_buck]$gt_cutoff +=1 ;
	else
       		TM_stats::stats_table[s_buck]$lt_cutoff +=1 ;

	for (a in cutoff_bytes)
       	{
       		if (bytes < cutoff_bytes[a] )
               	{
               		#print fmt ("a: %s conn > cutoff_bytes: %s, %s", a, conn_bytes, cutoff_bytes[a]);
                       	increment_bucket_cutoff(s_buck, a, bytes);
		}
	}


	if (bytes < T_64K)
		++TM_stats::stats_table[s_buck]$est$CUT_64K ;
	if (bytes < T_500K)
       		++TM_stats::stats_table[s_buck]$est$CUT_500K; 
	if (bytes < T_5M)
        	++TM_stats::stats_table[s_buck]$est$CUT_5M ; 
	if (bytes < T_5M)
       		++TM_stats::stats_table[s_buck]$est$CUT_25M ; 
} 


event Conn::log_conn (rec: Conn::Info)
{
	


		local conn_bytes = 0 ; 
	
		if (rec?$orig_bytes || rec?$resp_bytes)
			conn_bytes = rec$orig_bytes + rec$resp_bytes + rec$missed_bytes ; 
	
		if (rec$id$resp_p == 22/tcp)
		{ 
				populate_buckets_stats(SSH, conn_bytes, T_SSH); 
		} 


	 	if (rec$id$resp_p == 80/tcp)
                {
			populate_buckets_stats(HTTP, conn_bytes, T_HTTP);
                }	
	 	
		if (rec$id$resp_p == 443/tcp)
                {
			populate_buckets_stats(HTTPS, conn_bytes, T_HTTPS);
                }	
	
	

		if (rec$id$resp_p == 53/udp)
                {
			populate_buckets_stats(DNS, conn_bytes, T_DNS);
                }	

		if (rec$id$resp_p != 53/udp && rec$proto == udp)
		{ 
			populate_buckets_stats(UDP, conn_bytes, T_UDP);
                }


		if (rec$proto == icmp )
                {
		 	populate_buckets_stats(ICMP, conn_bytes, T_ICMP);
                }

		#if (rec$proto == smtp && (rec$id$resp_p == 25/tcp || rec$id$resp_p == 587/tcp ))
		if (rec$id$resp_p == 25/tcp || rec$id$resp_p == 587/tcp )
                {
			populate_buckets_stats(SMTP, conn_bytes, T_SMTP);
                }

		if (rec$proto != udp && rec$proto != icmp && rec$id$resp_p  != 22/tcp && rec$id$resp_p != 443/tcp && rec$id$resp_p != 25/tcp && rec$id$resp_p != 587/tcp && rec$id$resp_p != 53/udp && rec$id$resp_p != 80/tcp )
                {
			populate_buckets_stats(REST, conn_bytes, T_REST);	
                }
} 


event bro_done()
{

	event log_stats(stats_table); 
} 

