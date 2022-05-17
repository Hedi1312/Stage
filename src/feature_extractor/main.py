from random import randrange
import pandas as pd
from cve_feature_extractor import Cve_Feature_Extractor
import os
import sys
import consts
import csv
import time


filename = r'cve_feature_vectors.csv'
nbrOccurence = r'nombres_occurences.csv'


p = os.path.abspath('../matched_nvd_cves')
sys.path.insert(1, p)

from src.matched_nvd_cves.nvd import NvdCve

def main():
    start = time.time()
    msg = input("Souhaitez-vous télécharger les CVE des 13 dernières années ? Y/N\n")

    if "y" in msg or "Y" in msg:
        download_cves_json()

    print("En cours d'éxécution ...")

    # extract vector features from json files and write them into a csv file
    CveFeatureExtractor = Cve_Feature_Extractor()
    CveFeatureExtractor.feature_vectors_to_csv()

    # read csv into a pandas dataframe
    df_feature_vectors = pd.read_csv(consts.csv_url)

    print(df_feature_vectors.iloc[randrange(85000)])

    occurrences()

    end = time.time()

    print(end - start)

def download_cves_json():
    nvd_cve_downloader = NvdCve()

    # download json files
    nvd_cve_downloader.download_cve()

def occurrences():
    data = []

    with open(filename, encoding="utf8") as csvfile:
        csvreader = csv.reader(csvfile, delimiter=',')
        for row in csvreader:
            try:
                if len(row[3]) > 0 and "cwe_value" not in row:
                    data.append(row[3])
            except:
                continue


    # ouverture en écriture (w, première lettre de write) d'un fichier
    with open(nbrOccurence, 'w', newline='') as fichier:
        with open('../../data/arbre.txt') as arbre:
            arbre = arbre.read()

            # on déclare un objet writer
            ecrivain = csv.writer(fichier)

            # écrire une ligne dans le fichier:
            ecrivain.writerow(['cwe_value', 'occurences', 'presence_arbre'])

            # quelques lignes:
            for d in data:
                if d.split("-")[1] in arbre:
                    ecrivain.writerow([d, str(data.count(d)),"yes"])
                else:
                    ecrivain.writerow([d, str(data.count(d)),"no"])

    # défini une liste vide pour stocker les lignes uniques
    ls = []

    # ouvrir le fichier en lecture seule
    with open(nbrOccurence, 'r') as file:
        # lire le fichier ligne par ligne
        for line in file:
            # copier la ligne dans la liste si elle n'y est pas déjà
            if line not in ls:
                ls.append(line)

    # réouvrir le fichier mais en mode écriture (ce qui effacera le contenu existant) et écrire les lignes de la liste
    with open(nbrOccurence, 'w') as file:
        for line in ls:
            file.write(line)


# def trie():
#     with open('../../data/liste_not_in_arbre.csv') as not_in_arbre:
#         datafile_not_in_arbre = not_in_arbre.readlines()
#     not_in_arbre.close()
#
#     with open(filename) as vectorcsv:
#         datafile = vectorcsv.readlines()
#     vectorcsv.close()
#
#     for line in datafile:



if __name__ == "__main__":
    main()