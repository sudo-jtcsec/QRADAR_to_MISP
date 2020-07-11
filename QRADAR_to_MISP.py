import requests
import urllib3
import pymisp
import json
import argparse
from pymisp import MISPEvent, MISPAttribute
import urllib.parse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Format for integration
#{ 
#"Reference_Set_Name": name,
#"Type": ip|md5|url,
#"EventID": NEW|int
#"Attribute_Type: any
#}

#Function to create MISP event ***TO DO****
def create_misp_event(misp,distribution, t_level, analysis, info):
    event_obj = MISPEvent()
    event_obj.distribution = distribution
    event_obj.threat_level_id = t_level
    event_obj.analysis = analysis
    event_obj.info = info
    event = misp.add_event(event_obj)
    event_id = event.id

#Query QRadar for a reference set. Name must be URL encoded
def qrad_api_query_RS(set_name,qradip,api_token):
    url = "https://"+qradip+"/api/reference_data/sets/"+set_name
    headers = headers = { "Version": "12.0" , "Accept": "application/json", "SEC": api_token  }
    r = requests.get(url, headers=headers, verify=False)
    #return Reference set data in JSON form
    return json.loads(r.text)

#Connect to MISP isntance, return MISP object for additional calls
def misp_init(url,key,qdebug):
    misp = pymisp.PyMISP("https://"+url,key,ssl=False,debug=qdebug)
    return misp

#parse the integrations file and return them ina  JSON object
def get_integrations():
    f = open("integrations.json","r")
    f2j = ""
    for line in f:
        f2j += line.strip()
    f.close()
    return json.loads(f2j)

#Send API call to misp to add attributes to event
def update_misp(misp,mapping,qrad_ip,api_token):
    #Get plaintext reference set name from integrations list and URL encode it
    toEncode = mapping["Reference_Set_Name"]
    set_name = urllib.parse.quote(toEncode)
    #Query QRadar for reference set
    api_response = qrad_api_query_RS(set_name,qrad_ip,api_token)
    data_list = api_response["data"]
    #Query MISP for event to update
    event = misp.get_event(mapping["EventID"])
    #get all Attributes (aka IOCs ) from MISP event
    attributes = event["Event"]["Attribute"]
    #Check if data is already in teh event. If yes, pass. If no, add
    #***TO DO**** first seen/last seen dates
    is_in_misp = []
    for i in attributes:
        is_in_misp.append(i["value"])
    for d in data_list:
        if d["value"] in is_in_misp:
            pass
        else:
            attribute = MISPAttribute()
            attribute.value = d["value"]
            attribute.type = mapping["Attribute"]
            misp.add_attribute(mapping["EventID"],attribute)
    

def handle_args():
    parser = argparse.ArgumentParser(description='Export QRadar reference sets to MISP as attributes of an event')
    parser.add_argument('-l', dest = "list", help = "list all integrations with 'ALL' or specific UID")
    parser.add_argument('-i', dest = "id",  help = "run all integrations with 'ALL' or specific integration based off of UID")
    return parser

def main():
    parser = handle_args()
    args = parser.parse_args()
    if not args.list and not args.id:
        print("Wrong options. Stop. Run with -h to become enlightened")
        exit()
    print("**********************************************************************************")
    print("*    ____  _____           _              _          __  __ _____  _____ _____   *")
    print("*   / __ \|  __ \         | |            | |        |  \/  |_   _|/ ____|  __ \  *")
    print("*  | |  | | |__) |__ _  __| | __ _ _ __  | |_ ___   | \  / | | | | (___ | |__) | *")
    print("*  | |  | |  _  // _` |/ _` |/ _` | '__| | __/ _ \  | |\/| | | |  \___ \|  ___/  *")
    print("*  | |__| | | \ \ (_| | (_| | (_| | |    | || (_) | | |  | |_| |_ ____) | |      *")
    print("*   \___\_\_|  \_\__,_|\__,_|\__,_|_|     \__\___/  |_|  |_|_____|_____/|_|      *")
    print("*                                                                                *")
    print("**********************************************************************************\n")
    #Get appropriate keys from conf file
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
    if not api_token and not misp_key and not misp_ip and not qrad_ip:
        print("Not all of the neccessarry info was recieved. Your config files SUCKS!")
        exit()
    else:
        print("Got all config information required...\n")
    #load integrations file
    json = get_integrations()
    #print out existing integrations
    if args.list:
        if args.list=="ALL":
            count = 0
            for i in json["integrations"]:
                print("UID: "+str(count)+" "+str(i))
                count += 1
        else:
            print("UID: "+args.list+" "+str(json["integrations"][int(args.list)]))

    misp = misp_init(misp_ip,misp_key, False)
    #update misp events
    if args.id:
        if args.id == "ALL":
            for i in json["integrations"]:
                update_misp(misp,i,qrad_ip,api_token)
        else:
            update_misp(misp,json["integrations"][int(args.id)],qrad_ip,api_token)
        print("Update Success")
    
    #for i in json["integrations"]:
    #    update_misp(misp,i,qrad_ip,api_token)
    confile.close()
    


if __name__ == "__main__":
    main()
