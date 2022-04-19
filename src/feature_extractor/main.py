from random import randrange
import pandas as pd
from cve_feature_extractor import Cve_Feature_Extractor
import os
import sys
import consts

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

def download_cves_json():
    nvd_cve_downloader = NvdCve()

    # download json files
    nvd_cve_downloader.download_cve()


if __name__ == "__main__":
    main()