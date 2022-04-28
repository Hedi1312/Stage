import json

# fileObject = open("test2.json", "r")
# jsonContent = fileObject.read()
# data = json.loads(jsonContent)

with open('test2.json', 'r', encoding="utf8") as jsonfile:
    cve_list = json.load(jsonfile)

cves = cve_list['CVE_Items']

for cve in cves:
    id = cve['cve']['CVE_data_meta']['ID']

    # vendor name
    nodes = cve['configurations']['nodes']
    vuln_configs = 0
    vendor_tab = []


    for node in nodes:
        cpe_match = node['cpe_match']

        for config in cpe_match:

            cpe23Uri = config['cpe23Uri']
            if cpe23Uri.split(':')[3] not in vendor_tab:
                cpe = cpe23Uri.split(':')[3]
                vendor_tab.append(cpe.replace(",", ""))

            vendor_name = ":".join(vendor_tab)


    # try:
    #     cve['configurations']['nodes'][0]
    #     try:
    #         vendor = cve['configurations']['nodes'][0]['cpe_match'][0]['cpe23Uri'] + "\n"
    #     except:
    #         vendor = cve['configurations']['nodes'][0]['children'][0]['cpe_match'][0]['cpe23Uri'] + "\n"
    # except:
    #     continue

    print(id)
    # print(vendor)



# print(data['fruits'][0]['configurations']['nodes'][0]['cpe_match'][0]['cpe23Uri'])