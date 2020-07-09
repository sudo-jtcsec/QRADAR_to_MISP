import requests
import urllib3
import urllib.parse
import pymisp
import json
from pymisp import MISPEvent, MISPAttribute
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

confile = open("qrad.conf","r")
for line in confile:
    if "QRAD_API_KEY" in line:
        api_token = line.strip().split('=')[1]
        print("Got QRadar API Key")
    if "MISP_AUTH_KEY" in line:
        misp_key = line.strip().split('=')[1]
        print("Got MISP API Key")
    if "MISP_IP" in line:
        misp_ip = line.strip().split('=')[1]
        print("Got MISP IP")
    if "QRAD_IP" in line:
        qrad_ip = line.strip().split('=')[1]
        print("Got QRadar IP")
confile.close()

print("***************************************************************")
print("*                                                             *")
print("*  CLI Interface to add new integrations from QRadar to MISP  *")
print("*                                                             *")
print("***************************************************************\n\n")

ref_name = input("Enter name of QRadar Reference set to pull: ")
url = "https://"+qrad_ip+"/api/reference_data/sets/"+urllib.parse.quote(ref_name)
headers = headers = { "Version": "12.0" , "Accept": "application/json", "SEC": api_token  }
r = requests.get(url, headers=headers, verify=False)
print("Checking if reference set exists")
good = False
while good == False:
    if r.status_code == 200:
        good = True
    else:
        print("Unable to get reference set from API...\n")
        ref_name = input("Enter name of QRadar Reference set to pull: ")
        url = "https://"+qrad_ip+"/api/reference_data/sets/"+urllib.parse.quote(ref_name)
        headers = headers = { "Version": "12.0" , "Accept": "application/json", "SEC": api_token  }
        r = requests.get(url, headers=headers, verify=False)
print("Found reference set\n")
print("Checking for MISP API Access...")
misp = pymisp.PyMISP("https://"+misp_ip,misp_key,ssl=False,debug=False)
if misp:
    print("Got MISP object")
else:
    print("Unable to get to MISP. Your config SUCKS!")
    exit

checknew = input("Would you like to create a new event in MISP? Enter 'Y' if so, otherwise enter 'N' to use as existing event: ")
options = ["y","n","Y","N"]
wrong = False
while wrong == False:
    if checknew not in options:
        checknew = input("Please enter 'Y' or 'N': ")
    else:
        wrong = True
yes = ["Y","y"]
no = ["N","n"]
if checknew in no:
    print("\n")
    eventID = input("Enter the Event ID from MISP to add to: ")
    event = misp.get_event(eventID)
    if event:
        print("Got '"+event["Event"]["info"]+ "' Event from MISP")
    else:
        print("Unable to loacte MISP event. Stop.")
        exit
    a_type = input("Enter data type: ip-src|ip-dst|md5|url")
    while a_type not in ["ip-src","ip-dst","md5","url"]:
        a_type = input("Enter data type: ip-src|ip-dst|md5|url : ")
    print("got all data")

ints = open("integrations.json","r")
f2j = ""
for line in ints:
    f2j += line.strip()
ints.close()
jsonified = json.loads(f2j)
eventdict = {"Reference_Set_Name": ref_name, "EventID": eventID, "Attribute": a_type }
jsonified["integrations"].append(eventdict)
ints = open("integrations.json","w")
json.dump(jsonified,ints)
ints.close()
