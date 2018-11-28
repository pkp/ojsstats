# git pull, then parse logs on Mondays
50 9 * * 1 cd /home/pkp_tracker/ojsstats; git pull; cp d3/* /var/www/html/pkp_www/files/ojsstats/d3/.; python ojsstats.py;

# on Thursdays, crunch numbers
30 23 * * 4 cd /home/pkp_tracker/ojsstats; scl enable python27 "python statscrunch.py"

# finally, on Friday mornings, copy the output data to where d3 can use it, and save old numbers
30 10 * * 5 cd /home/pkp_tracker/ojsstats; ./final_munge.sh
