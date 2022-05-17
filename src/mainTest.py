import json
import re

def main():
    global cluster, prim_cluster, sec_cluster
    to_ignore = ('REJECT', 'DISPUTED', 'Resolved')
    when_assigned = ('UNSUPPORTED WHEN ASSIGNED', 'PRODUCT NOT SUPPORTED WHEN ASSIGNED', 'VERSION NOT SUPPORTED WHEN ASSIGNED')

    with open('..//data/nvd/nvdcve-1.1-2010.json', 'r', encoding="utf8") as jsonfile:
        cve_list = json.load(jsonfile)
    jsonfile.close()

    cves = cve_list['CVE_Items']
    cwe_non_present = []
    clusters = []
    clusters_final = []
    cwe_double = []

    for cve in cves:
        cve_id = cve['cve']['CVE_data_meta']['ID']

        # vendor name
        nodes = cve['configurations']['nodes']
        vuln_configs = 0
        vendor_tab = []
        product_tab = []


        # cwe value
        cwe = cve['cve']['problemtype']['problemtype_data'][0]['description']
        if (len(cwe) > 0):
            cwe_value = cwe[0]['value']
            cwe_value_split = str(cwe_value.split("-")[1])
        else:
            continue

        if cwe_value == "NVD-CWE-noinfo" or cwe_value == "NVD-CWE-Other" or cwe_value == "CWE-254" or cwe_value =="CWE-199" or cwe_value =="CWE-216" or cwe_value =="CWE-1278":
            continue

        summary = cve['cve']['description']['description_data'][0]['value']

        # if summary.startswith('**'):
        #     special_message = summary.split('**')[1].strip()
        #
        #     if special_message in to_ignore:
        #         continue
        #     elif special_message in when_assigned:
        #         unsupported_when_assigned = 1
        #
        # clean_summary = get_clean_summary(summary)


        # Primary cluster

        with open('../data/arbre.txt') as arbre:
            datafile = arbre.readlines()
        arbre.close()

        with open('../data/liste_not_in_arbre.csv') as not_in_arbre:
            datafile_not_in_arbre = not_in_arbre.readlines()
        not_in_arbre.close()

        cwe_non_present.append(cwe_value_split)

        clusters = []
        clusters_final = []
        prim_clusters = []
        sec_clusters = []
        cwe_double = []

        for line in datafile:
            if '(' + cwe_value_split + ')' in line:
                if cwe_value_split in cwe_non_present:
                    cwe_non_present.remove(cwe_value_split)

                n = cwe_value_split

                if "Primary Cluster" in line:
                    cluster = n + '-' + n + '-' + n
                    prim_cluster = n
                    sec_cluster = 0
                else:
                    m = find_primary_cluster(line)

                if "Secondary Cluster" in line:
                    cluster = n + '-' + m + '-' + n
                    prim_cluster = m
                    sec_cluster = n

                else:
                    x = find_secondary_cluster(line)
                    cluster = n + '-' + x + '-' + m
                    prim_cluster = m
                    sec_cluster = x

                if cve_id + ':' + cluster not in clusters:
                    clusters.append(cve_id + ':' + cluster)
                    prim_clusters.append(prim_cluster)
                    sec_clusters.append(sec_cluster)
                    clusters_final.append(cluster)

                else:
                    cwe_double.append(cve_id + ':' + cluster)

            else:
                for l in datafile_not_in_arbre:
                    if "CWE-"+cwe_value_split == l.split(",")[0]:
                        prim_cluster = l.split(",")[1].split("-")[1]
                        sec_cluster = l.split(",")[2].split("-")[1]
                        cluster = cwe_value_split + "-" + sec_cluster.rstrip() + "-" + prim_cluster

                        if cve_id + ':' + cluster not in clusters:
                            clusters.append(cve_id + ':' + cluster)
                            clusters_final.append(cluster)
                        else:
                            cwe_double.append(cve_id + ':' + cluster)

        print(cve_id, cwe_value_split, clusters_final)


def find_primary_cluster(l):
    # Pour trouver le primary cluster de la cwe à la ligne l
    # Itérer sur le fichier et trouver le numéro de ligne m le plus grand, qui contient la phrase primary cluster, mais qui est plus petit que l.

    with open('../data/arbre.txt') as arbre:
        global primary_cluster

        datafile = arbre.readlines()
        arbre.close()
        primary = []
        ligne = []

        for i, line in enumerate(datafile, 1):
            if l in line:
                num_line_l = i

            if "Primary Cluster" in line:
                primary.append(str(i)+line)

        for p in primary:
            num_line_m = p.split("-")[0]

            if int(num_line_m) < num_line_l:
                ligne.append(p)

        primary_cluster = str(ligne[-1])
        primary_cluster = re.findall(r"\(\s*\+?(-?\d+)\s*\)", primary_cluster)
        primary_cluster = str(primary_cluster)
        primary_cluster = primary_cluster.split("'")[1]

        return primary_cluster


def find_secondary_cluster(l):

    # Pour trouver le secondary cluster de la cwe à la ligne n
    # Trouver le primary cluster m de l, avec la fonction précédente. Puis chercher le plus grand index de ligne x tel que x est plus grand que m, mais plus petit que n.
    good_secondary_cluster = []
    m = find_primary_cluster(l)
    m = str('(' + m + ')')

    n = re.findall(r"\(\s*\+?(-?\d+)\s*\)", l)
    n = str(n)
    n = n.split("'")[1]
    n = str('(' + n + ')')


    with open('../data/arbre.txt') as arbre:
        global secondary_cluster
        secondary_cluster = str(0)

        datafile = arbre.readlines()
        arbre.close()
        secondarys = []

        for i, line in enumerate(datafile, 1):
            if n in line:
                num_line_n = int(i)

            if m in line:
                num_line_m = int(i)

            if "Secondary Cluster" in line:
                secondarys.append(str(i)+line)

        for s in secondarys:
            num_line_x = s.split('-')[0]
            num_line_x = int(num_line_x)

            if num_line_x > num_line_m and num_line_x < num_line_n:
                good_secondary_cluster.append(s)

        if len(good_secondary_cluster) == 0:
            return "Absent"

        else:
            secondary_cluster = str(good_secondary_cluster[-1])
            secondary_cluster = re.findall(r"\(\s*\+?(-?\d+)\s*\)", secondary_cluster)
            secondary_cluster = str(secondary_cluster)
            secondary_cluster = secondary_cluster.split("'")[1]

            return secondary_cluster



if __name__ == "__main__":
    main()