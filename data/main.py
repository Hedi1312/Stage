import re

def main():
    test = []
    cwe = 787
    test.append(find_cluster(cwe))
    print(test)

def find_cluster(cwe):
    with open('arbre.txt') as arbre:
        datafile = arbre.readlines()
    arbre.close()

    with open('liste_not_in_arbre.csv') as not_in_arbre:
        datafile_not_in_arbre = not_in_arbre.readlines()
    not_in_arbre.close()

    cwe = str(cwe)
    p = []
    for line in datafile:
        if '(' + cwe + ')' in line:
            if "Primary Cluster" in line:
                return "Primary cluster : " + cwe + ", secondary cluster : aucun, fichier : arbre.txt"

            else:
                m = find_primary_cluster(line)

            if "Secondary Cluster" in line:
                return "Primary cluster : " + m + ", secondary cluster : " + cwe + ", fichier : arbre.txt"

            else:
                x = find_secondary_cluster(line)
                return "Primary cluster : " + m + ", secondary cluster : " + x + ", fichier : arbre.txt"

        else:
            for l in datafile_not_in_arbre:
                if "CWE-"+cwe == l.split(",")[0]:
                    prim_cluster = l.split(",")[1].split("-")[1]
                    sec_cluster = l.split(",")[2].split("-")[1].split("\n")[0]
                    return "Primary cluster : " + prim_cluster + ", secondary cluster : " + sec_cluster.rstrip() + ", fichier : liste_no_arbre.csv"


def find_primary_cluster(l):
    with open('arbre.txt') as arbre:
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
    good_secondary_cluster = []
    m = find_primary_cluster(l)
    m = str('(' + m + ')')

    n = re.findall(r"\(\s*\+?(-?\d+)\s*\)", l)
    n = str(n)
    n = n.split("'")[1]
    n = str('(' + n + ')')


    with open('arbre.txt') as arbre:
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