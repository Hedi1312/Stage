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

cves = ["CVE-2013-3582", "CVE-2010-1000", "CVE-2010-0104"]

for c in cves:

    id = c

    with open('../data/data.csv') as file:
        datafile= file.readlines()
    file.close()

    for d in datafile:

        if id in d:
            if len(d.split(',')[1].rstrip()) == 1:
                label = d.split(',')[1].rstrip()+'-'+"Iot"
                break
            else:
                label = d.split(',')[1].rstrip()+'-'+"No_Iot"
                break
        else:
            label = "no_data"


    print(label)