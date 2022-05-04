import json

# fileObject = open("test2.json", "r")
# jsonContent = fileObject.read()
# data = json.loads(jsonContent)

with open('../data/nvd/nvdcve-1.1-2016.json', 'r', encoding="utf8") as jsonfile:
    cve_list = json.load(jsonfile)

cves = cve_list['CVE_Items']

for cve in cves:
    id = cve['cve']['CVE_data_meta']['ID']

    # vendor name
    nodes = cve['configurations']['nodes']
    vuln_configs = 0
    vendor_tab = []
    product_tab = []


    for node in nodes:
        children = node['children']
        cpe_match2 = node['cpe_match']

        for config2 in cpe_match2:

            cpe23Uri2 = config2['cpe23Uri']
            if cpe23Uri2.split(':')[3] not in vendor_tab:
                cpe2 = cpe23Uri2.split(':')[3]
                vendor_tab.append(cpe2.replace(",", ""))

            if cpe23Uri2.split(':')[4] not in product_tab:
                product2 = cpe23Uri2.split(':')[4]
                product_tab.append(product2.replace(",", ""))


        for config in children:
            cpe_match = config['cpe_match']
            for c in cpe_match:
                cpe23Uri = c['cpe23Uri']
                if cpe23Uri.split(':')[3] not in vendor_tab:
                    cpe = cpe23Uri.split(':')[3]
                    vendor_tab.append(cpe.replace(",", ""))

                if cpe23Uri.split(':')[4] not in product_tab:
                    product = cpe23Uri.split(':')[4]
                    product_tab.append(product.replace(",", ""))


        vendor_name = ":".join(vendor_tab)
        product_name = ":".join(product_tab)

        print(id+'\t'+vendor_name+'\t'+product_name)



