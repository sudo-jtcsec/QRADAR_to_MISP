import requests
import urllib3
import pymisp
import json
from pymisp import MISPEvent, MISPAttribute
import urllib.parse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Format
#{ 
#"Reference_Set_Name": name,
#"Type": ip|md5|url,
#"EventID": NEW|int
#"Attribute_Type: any
#}

def create_misp_event(misp,distribution, t_level, analysis, info):
    event_obj = MISPEvent()
    event_obj.distribution = distribution
    event_obj.threat_level_id = t_level
    event_obj.analysis = analysis
    event_obj.info = info
    event = misp.add_event(event_obj)
    event_id = event.id

def qrad_api_query_RS(set_name,qradip,api_token):
    url = "https://"+qradip+"/api/reference_data/sets/"+set_name
    headers = headers = { "Version": "12.0" , "Accept": "application/json", "SEC": api_token  }
    r = requests.get(url, headers=headers, verify=False)
    return json.loads(r.text)

def misp_init(url,key):
    misp = pymisp.PyMISP("https://"+url,key,ssl=False,debug=True)
    return misp

def get_integrations():
    f = open("integrations.json","r")
    f2j = ""
    for line in f:
        f2j += line.strip()
    f.close()
    return json.loads(f2j)

def update_misp(misp,mapping,qrad_ip,api_token):
    toEncode = mapping["Reference_Set_Name"]
    set_name = urllib.parse.quote(toEncode)
    api_response = qrad_api_query_RS(set_name,qrad_ip,api_token)
    data_list = api_response["data"]
    event = misp.get_event(mapping["EventID"])
    attributes = event["Event"]["Attribute"]
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

def main():
    confile = open("servers.conf","r")
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

    misp = misp_init(misp_ip,misp_key)

    json = get_integrations()
    print(type(json))
    for i in json["integrations"]:
        update_misp(misp,i,qrad_ip,api_token)
    #misp.get_event(81)
    confile.close()
    


if __name__ == "__main__":
    main()
