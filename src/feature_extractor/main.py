from random import randrange
import pandas as pd
from cve_feature_extractor import Cve_Feature_Extractor
import os
import sys
import consts
import csv

filename = r'cve_feature_vectors.csv'



p = os.path.abspath('../matched_nvd_cves')
sys.path.insert(1, p)

from src.matched_nvd_cves.nvd import NvdCve

def main():

    download_cves_json()

    # extract vector features from json files and write them into a csv file
    CveFeatureExtractor = Cve_Feature_Extractor()
    CveFeatureExtractor.feature_vectors_to_csv()

    # read csv into a pandas dataframe
    df_feature_vectors = pd.read_csv(consts.csv_url)

    print(df_feature_vectors.iloc[randrange(85000)])

    occurrences()

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
                if len(row[2]) > 0 and "cwe_value" not in row:
                    data.append(row[2])
            except:
                continue

    # ouverture en écriture (w, première lettre de write) d'un fichier
    with open('nombres_occurences.csv', 'w', newline='') as fichier:

        # on déclare un objet writer
        ecrivain = csv.writer(fichier)

        # écrire une ligne dans le fichier:
        ecrivain.writerow(['cwe_value', 'occurences'])

        # quelques lignes:
        for d in data:
            ecrivain.writerow([d, str(data.count(d))])



if __name__ == "__main__":
    main()