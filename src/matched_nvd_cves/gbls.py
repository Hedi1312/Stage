"""Define Global variables and constants.

sccmgbls defines all global variables and constants.

See utils for initialization of default values.
"""

# separate individual values in a particular field
SEP = "|"
SEP2 = ","
HASH = '#'

df_cpe4 = 'rf_df_cpe4'
df_cve = 'rf_df_cve'
df_assets_cpe_pck = 'rf_df_cve'
df_cpe4_pck = 'rf_df_cpe4.pck'
df_cpe4_csv = ' rf_df_cpe4.csv'
df_cve_pck = 'rf_df_cve.pck'
df_cve_csv = 'rf_df_cve.csv'
df_assets_cpe_pck = 'rf_df_cve.pck'
df_assets_cpe_csv = 'rf_df_cve.csv'
# cleaning_words_path = 'c:/nvd/cleaning_words.csv'

####### organization inventory
# org_inventory = '/home/rayan/stage/nvd/inventory.csv' # addrees to the inventory

# ######## stanza resource address
# stanza_path = '/home/rayan/stage/stanza_resources1'

######matched cve filename
# matched_nvd_cves = '/home/rayan/stage/nvd/matched_nvd_cves.csv'
# matched_assets ='/home/rayan/stage/nvd/matched_assets.csv'
#   NVD data
######
# nvdcpe = '/home/rayan/stage/nvd/official-cpe-dictionary_v2.3.xml'  # directory for cpe dictionary
nvdcve = "C:\\Users\\hedio\\Documents\\Stage\\data\\nvd\\nvdcve-1.1-"  # directory for cve dictionary
nvddir = "C:\\Users\\hedio\\Documents\\Stage\\data\\nvd"

# Downloads
url_meta_base = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-'  # e.g. https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.meta
url_meta_end = '.meta'
url_json_base = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-'
url_json_middle = ''
url_json_end = '.json.zip'
url_cpe = 'http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip'

cpe_filename = 'official-cpe-dictionary_v2.3.xml'
cpe_max_age = 7

cve_filename = 'nvdcve-1.1-'

#   Number of years of NVD CVD XML feed files
num_nvd_files = 10

nvd_meta_filename = 'cve_meta_'
