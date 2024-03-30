# python_eventgen
log eventgen using python


By default the script folder should be written to /opt on a linux install.  If you do this, the python will just work, if not you will need to change the path location for the files.  
The python script will read and write files to a specific path.  You will need to have that path on your machine, or change the path to make the code work.  The important locations for changing logs is 
line 690 - change location you write your new logs to 
line 694 - change location that you read the scenario details from.
line 699 - change location for script scenario metadata file.
line 704 - change location for the csv that has your inventory
