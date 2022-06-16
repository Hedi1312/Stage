# a = "allo attack vulner user"
#
# with open('../data/word_more_frequent.csv') as file:
#     datafile= file.readlines()
# file.close()
#
# word_more_frequent = []
# for i in datafile:
#     word_more_frequent.append(i.rstrip())
#
# b = ''
#
# for w in word_more_frequent:
#     if w in a:
#         b = b + str(1) + '-'
#     else:
#         b = b + str(0)+ '-'
#
# print(b)
# print(len(b))
# print(b.rstrip('-'))
# print(len(b))

# import os
#
# with open('../data/data.csv') as file:
#     datafile= file.readlines()
# file.close()
#
# if os.path.exists("../data/data_2010_2019.csv"):
#     os.remove("../data/data_2010_2019.csv")
#
# fichier = open("../data/data_2010_2019.csv", 'a')
#
# for d in datafile:
#     if len(d.split(',')[1].rstrip()) == 1:
#         label = "Iot"
#
#     else:
#         label = "No_Iot"
#
#     fichier.write(d.split(',')[0]+","+label+"\n")

# with open('../data/nvd/nvdcve-1.1-2010.json') as file:
#     datafile= file.readlines()
# file.close()
import json
with open('../data/nvd/nvdcve-1.1-2010.json', 'r', encoding="utf8") as jsonfile:
    cve_list = json.load(jsonfile)

cves = cve_list['CVE_Items']


for cve in cves:
    cve_id = cve['cve']['CVE_data_meta']['ID']
    cve_id = str(cve_id)
    nodes = cve['configurations']['nodes']
    label_tab = []

    for node in nodes:
        children = node['children']
        cpe_match2 = node['cpe_match']

        for config in children:
            cpe_match = config['cpe_match']
            for c in cpe_match:
                cpe23Uri = c['cpe23Uri']
                if cpe23Uri.split(':')[2] not in label_tab:
                    label = cpe23Uri.split(':')[2]
                    label_tab.append(label.replace(",", ""))


    if not label_tab:
        test = cve_id, label_tab, "no_data"
    else:
        for io in label_tab:
            if "h" in io:
                test = cve_id, label_tab, "iot"
            else:
                test = cve_id, label_tab, "non_iot"
    print(test)
