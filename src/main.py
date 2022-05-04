import json

# fileObject = open("test2.json", "r")
# jsonContent = fileObject.read()
# data = json.loads(jsonContent)

with open('test.json', 'r', encoding="utf8") as jsonfile:
    cve_list = json.load(jsonfile)

cves = cve_list['CVE_Items']
cwe_non_present = []

for cve in cves:
    id = cve['cve']['CVE_data_meta']['ID']

    # vendor name
    nodes = cve['configurations']['nodes']
    vuln_configs = 0
    vendor_tab = []
    product_tab = []


    # cwe value
    cwe = cve['cve']['problemtype']['problemtype_data'][0]['description']
    if (len(cwe) > 0):
        cwe_value = cwe[0]['value']
        cwe_split = str(cwe_value.split("-")[1])
    else:
        continue

    if cwe_value == "NVD-CWE-noinfo":
        continue

    # Primary cluster

    with open('../data/arbre.txt') as arbre:
        datafile = arbre.readlines()

    print(cwe_value + '\t' + cwe_split)
    cwe_non_present.append(cwe_split)

    for line in datafile:
        if cwe_split in line:
            n = line
            cwe_non_present.remove(cwe_split)

print(cwe_non_present)
print(n)