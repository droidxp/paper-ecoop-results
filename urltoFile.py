import sys
import csv

from time import sleep
VTKey = "Ask for a Key at VirusTotal and put here"
if sys.version_info[0] == 3:
    from urllib.request import urlopen
else:
    # Not Python 3 - today, it is most likely to be Python 2
    # But note that this might need an update when Python 4
    # might be around one day
    from urllib import urlopen

#create a list with app hash that you want to get Virus Total information on JSON file format (listRepackageHash.csv)
#with this JSON file you can use avclass (https://github.com/malicialab/avclass) to label family malware app
with open('listRepackageHash.csv') as csvfile:
    readCSV = csv.reader(csvfile, delimiter=',')
    for row in readCSV:
        with urlopen("https://www.virustotal.com/vtapi/v2/file/report?apikey="+VTkey+"&resource="+row[0]) as url:
            s = url.read()
            text_file = open(row[0]+".json", "wb")
            text_file.write(s)
            text_file.close()
            sleep(4)
