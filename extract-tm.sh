#!/usr/local/bin/bash

runat=$(date "+%Y-%m-%d-%H-%M-%S")
WORKDIR="/tmp/extract-$runat"
mkdir -p $WORKDIR 

DATA_MOUNTS="/TM/ /TM-SMTP/" 

declare -a slice_map

run_log="$WORKDIR/run.log" 

function convert_to_unix()
{
	date_string=$1 

	cmd1="date -j -f \"%B %d %H:%M:%S %Y\" "
	cmd2=" +%s" 

	date_cmd=$cmd1 ; 

	date_cmd+=$date_string 
	date_cmd+=$cmd2 

	epoch=$(eval $date_cmd) 

	echo $epoch 
}

function generate_tcpslice_out_find()
{

	echo "bucketname is: $BUCKET_NAME" 
  echo "Calculating number of days in $FILE_NAME......" | tee -a $WORKDIR/run.log

	class_file="\*class_" 
	class_file+="$BUCKET_NAME"
	class_file+="\_*" 

        days=$(awk '{print $1}' $FILE_NAME | sort | uniq  | cf -f "%F-%T" | awk -F"-"  '{print $1"/"$2"/"$3}' - | sort | uniq)

        echo    | tee -a $WORKDIR/run.log

        for day in $days;
        do
                echo $day
                echo "Generating tcpslice for $day..." | tee -a $WORKDIR/run.log
        	nextday=$( date -j -v+1d  -f "%Y/%m/%d" "$day"  "+%Y/%m/%d")
		#echo "find -L $DATA_MOUNTS -name  $class_file -type f -newermt $day ! -newermt $nextday -print | sort -k1" 
	       	filelist=$(find -L $DATA_MOUNTS -name "*$BUCKET_NAME\_*" -type f -newermt $day ! -newermt $nextday -print | sort -k1 )
                filename=$(echo $day | sed 's/\//-/g' )
	
		for file in $filelist; do 
			#echo "tcpslice -R $file  |  sed -e 's/\.[0-9]*//2;s/\.[0-9]*//2' -e 's/ *$//'  >> $WORKDIR/$filename-tcpslice.out"
			#echo "tcpslice -R $file  |  sed -e 's/\.[0-9]*//2;s/\.[0-9]*//2' -e 's/ *$//' >> $WORKDIR/$filename-tcpslice.out"
			tcpslice -R $file  |  sed -e 's/\.[0-9]*//2;s/\.[0-9]*//2' -e 's/ *$//' >> $WORKDIR/$filename-tcpslice.out ;
		done 
                cat $WORKDIR/$filename-tcpslice.out >> $WORKDIR/tcpslice.out
        done

        echo "Finished generating tcpslice output" | tee -a $WORKDIR/run.log
        echo "=======================================" | tee -a $WORKDIR/run.log

}	

function generate_tcpslice_out()
{
	echo "Calculating number of days in $FILE_NAME......" | tee -a $WORKDIR/run.log 
	
	days=$(awk '{print $1}' $FILE_NAME | sort | uniq  | cf -f "%F-%T" | awk -F"-"  '{print $1"/"$2"/"$3}' - | sort | uniq) 
	nextday=$( date -j -v+1d  -f "%Y/%m/%d" "$day"  "+%Y/%m/%d")

	find /TM-SMTP/ -type f -newermt 2014/11/18 ! -newermt 2014/11/19 -name "*" -print
	

	echo 	| tee -a $WORKDIR/run.log

	for day in $days;
	do 
		echo $day 
		echo "Generating tcpslice for $day..." | tee -a $WORKDIR/run.log
		path="/TMquick/$day" ; 
		filename=$(echo $day | sed 's/\//-/g' ) 
		echo "tcpslice -R $path/$BUCKET_NAME*  | sed -e 's/\.[0-9]*//g' -e 's/ *$//' > $WORKDIR/$filename-tcpslice.out" 
		tcpslice -R $path/$BUCKET_NAME* | sed -e 's/\.[0-9]*//g' -e 's/ *$//' >> $WORKDIR/$filename-tcpslice.out ; 
		cat $WORKDIR/$filename-tcpslice.out >> $WORKDIR/tcpslice.out 
	done 
	
	echo "Finished generating tcpslice output" | tee -a $WORKDIR/run.log
	echo "=======================================" | tee -a $WORKDIR/run.log
}


function binary_search()
{
        ts=$1
	
        ary_size=${#slice_map[@]};

        let low=0 ;
        let high=ary_size


   while (( "$low" < "$high" )); do
        let mmid=low+high
        let mid=mmid/2

	start=$( echo ${slice_map[$mid]} | awk -F"," '{print $1}' - | sed -e 's/\.[0-9]*//g' )
        end=$( echo ${slice_map[$mid]} | awk -F"," '{print $2}' - | sed -e 's/\.[0-9]*//g' )
        bucket=$( echo ${slice_map[$mid]} | awk -F"," '{print $3}' - )
        
	if [ "$end" -lt  "$ts" ]; then
            let low=mid+1
        elif [ "$start" -gt "$ts" ]; then
            let high=mid;

        else
                result=$(echo ${slice_map[$mid]} | awk -F"," '{print $3}' - )
		echo $result  
                break ;
        fi

   done
	
}

## /TMquick/2015/06/02/smtp-00:12:45       Tue Jun  2 00:12:45 2015        Tue Jun  2 00:35:56 2015

function gen_tcpslice_map()
{

awk '{print $2","$3","$1}' $WORKDIR/tcpslice.out  >> $WORKDIR/tcpslice.map 

return 

####readarray -t myarray < $WORKDIR/tcpslice.out
readarray -t myarray < /YURT/tmp/extract-2015-06-12-15-10-47/tcpslice.out

# Explicitly report array content.
let i=0
let j=0
while (( ${#myarray[@]} > i )); do

    start_time=$(echo "${myarray[i]}" | awk '{print $3" "$4" "$5" "$6}' - )
    end_time=$(echo "${myarray[i]}" | awk '{print $8" "$9" "$10" "$11}' - )
    bucket_file=$(echo "${myarray[i]}" | awk '{print $1}' - )

        #echo $start_time, $end_time, $bucket_file

        start=$(convert_to_unix "'$start_time'");
        end=$(convert_to_unix "'$end_time'") ;

        #echo "$start, $end, $bucket_file" 

        echo $start, $end, $bucket_file >> $WORKDIR/tcpslice.map
        let i+=1
done

}

function read_tcpslice_map()
{

readarray slice_map < $WORKDIR/tcpslice.map

echo "Generating slice Map now, for faster searching...." 
echo "Size of slice-map is ${#slice_map[@]} " 
}



function find_bucket()
{

	timestamp=$1 
	#echo "timestamp is $timestamp" 
	
	# /TMquick/2015/06/02/smtp-00:12:45 Tue Jun 2 00:12:45 2015 Tue Jun 2 00:35:56 2015
	while read line           
	do           
		start_time=$(echo $line | awk '{print $3, $4, $5}' - )
		end_time=$(echo $line | awk '{print $8, $9,$10}' - ) 

		bucket_file=$(echo $line | awk '{print $1}' - )
		echo $start_time,  $end_time 
		start=$(convert_to_unix "'$start_time'");
		end=$(convert_to_unix "'$end_time'") ;

		echo "Start: $start, End: $end"

		if [[ ("$timestamp" > "$start")  && ("$timestamp" < "$end") ]] ; then 
			echo $bucket_file 
		fi 
	done <  $WORKDIR/tcpslice.out

} 


function extract_pcaps()
{
filter=''
bucket_file='' 
old_bucket='' 
bucket_count=0 
FIRST_RUN=0 
all_cid='' 
let sessions_count=1 

while read -r line 
	do 
		### parse line and populate the variables 
	
		timestamp=$( echo $line | awk '{print $1}' - )	
		cid=$(echo $line | awk '{print $2}' - ) 
		host=$(echo $line | awk '{print $3}' - ) 
		port=$(echo $line | awk '{print $4}' - ) 

		# find the right bucket for the timestamp 
		## decomissioning find_bucket for speedy binary_search(!!)
		#bucket_file=$(find_bucket  $timestamp ) 

		ts=$(echo $timestamp | awk -F"." '{print $1}'  - )
		bucket_file=$(binary_search "$ts" ) 

	
		#echo "timestamp is $timestamp"
		#echo "bucket_file is $bucket_file" 

		## gather connection identifiers 	

		## check if new bucket has emerged 
		## if so, then tcpdump previous set of filters on previous bucket

		if [ "$old_bucket" != "$bucket_file" ]; then 
			if [ "$filter" != "" ]; then
				echo | tee -a $WORKDIR/run.log
				echo "Extracting pcaps from: $old_bucket: " | tee -a $WORKDIR/run.log
				echo "Sessions: $all_cid" | tee -a $WORKDIR/run.log
				echo "Bucket : $old_bucket" | tee -a $WORKDIR/run.log
				echo "command: tcpdump -nr $old_bucket -w bucket-$bucket_count-$sessions_count-sessions.pcap '$filter'" | tee -a $WORKDIR/run.log
				echo "Sessions count is $sessions_count"  | tee -a $WORKDIR/run.log 
				tcpdump -nr $old_bucket -w $bucket_count-$sessions_count-Sessions.pcap $filter
				####tcpdump -nr $old_bucket -w $bucket_count-$all_cid.pcap $filter
				echo | tee -a $WORKDIR/run.log
				echo "====================================================" | tee -a $WORKDIR/run.log
				all_cid='' 
				let sessions_count=0 
			fi

			filter='( host '$host'  and port '$port' )' 
			let "bucket_count+=1"
			all_cid=$cid 
			let sessions_count+=1 
		else 
			filter+=' or ( host '$host' and port '$port' )'
			all_cid+="-"$cid 
			let sessions_count+=1  
		fi 

		old_bucket=$bucket_file
done < <(cat $FILE_NAME )

echo | tee -a $WORKDIR/run.log
echo "Extracting pcaps from: $old_bucket" | tee -a $WORKDIR/run.log
echo "command: tcpdump -nr $old_bucket -w bucket-$bucket_count-$sessions_count-sessions.pcap '$filter'" | tee -a $WORKDIR/run.log
echo "Sessions count is $sessions_count"  | tee -a $WORKDIR/run.log 
tcpdump -nr $old_bucket -w $bucket_count-$sessions_count-Sessions.pcap $filter

echo "=========== pcap extraction done ======================" | tee -a $WORKDIR/run.log


#		if [ -z "$filter" ]; then 	
#			filter='( host '$host'  and port '$port' )' 
#		else 
#			filter+=' or ( host '$host' and port '$port' )'
#		fi 

} 


function run_bro_on_pcaps()
{

	cd $WORKDIR 

	echo | tee -a $WORKDIR/run.log
	echo "Merging pcaps to ALL.pcap"  | tee -a $WORKDIR/run.log
	echo 	| tee -a $WORKDIR/run.log
	ipsumdump -q --collate -w $WORKDIR/ALL.pcap *.pcap 


	BRODIR="$WORKDIR/BRO"
	mkdir -p $BRODIR 
	cp $WORKDIR/ALL.pcap $BRODIR 
	cd $BRODIR 
	echo | tee -a $WORKDIR/run.log
	echo | tee -a $WORKDIR/run.log
	echo "RUnnning bro now .......on $BRODIR/ALL.pcap " | tee -a $WORKDIR/run.log
	bro -r ALL.pcap local >& /dev/null 
	cd $WORKDIR 

	echo | tee -a $WORKDIR/run.log
	echo "BRO finished - logs created, files exteracted (see extract_files dir)" | tee -a $WORKDIR/run.log
	echo | tee -a $WORKDIR/run.log
} 

		
		


if [ -z "$1" ]; then 
	echo "Need the name of the Bro log file to extract data from?"
	echo "syntax: extract-tm <file_name> <bucket_name>" 
	exit ; 
fi 


if [ -z "$2" ]; then 
	echo "Need the name of the bucket to extract data from?"
	echo "syntax: extract-tm <file_name> <bucket_name>" 
	exit ; 
fi 


let RUN_BRO=0

while true; do
        read -p "Do you want to run bro on the pcaps? (y/n/q)?" yn
        case $yn in
        [Yy]* ) let RUN_BRO=1; break ;;
        [Nn]* ) break;;
        [Qq]* ) exit;;
        * ) echo "Please answer yes or no or quit.";;
    esac
done


FILE_NAME="$1" 
echo $FILE_NAME 

if ! [ -e "$FILE_NAME" ]; then 
	echo "File doesn't exist, don't play with me, I got work to do"
	exit 
fi 

cp $FILE_NAME $WORKDIR/

BUCKET_NAME=$2 

if [ "$BUCKET_NAME" == "all" ] || [ "$BUCKET_NAME" == "dns" ] || [ "$BUCKET_NAME" == "http" ] || [ "$BUCKET_NAME" == "smtp" ] || [ "$BUCKET_NAME" == "udp" ] || [ "$BUCKET_NAME" == "https" ] ; then
	echo "OK searching $BUCKET_NAME logs" 
else
	echo "Incorrect bucket name"
	exit 
fi 



echo "================================="| tee -a $WORKDIR/run.log
echo "Extraction will be in : $WORKDIR" | tee -a $WORKDIR/run.log
echo "================================="| tee -a $WORKDIR/run.log
cd $WORKDIR 



#generate_tcpslice_out
generate_tcpslice_out_find 
gen_tcpslice_map
echo "Finished generating slice map......." 
echo "Reading slice map now ......." 
read_tcpslice_map
echo "Finished reading slice map......." 

echo "extracting pcaps ......." 
extract_pcaps

if [ "$RUN_BRO" -eq "1" ]; then
	echo "Running bro on the pcaps" | tee -a $WORKDIR/run.log
	run_bro_on_pcaps
fi


echo "+==================================="| tee -a $WORKDIR/run.log
echo " Pcaps and data is in $WORKDIR" | tee -a $WORKDIR/run.log
echo "+==================================="| tee -a $WORKDIR/run.log
