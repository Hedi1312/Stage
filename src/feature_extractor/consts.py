path_nvd = 'C:\\Users\\hedio\\Documents\\Stage\\data\\nvd\\'
path_featureExtractor = 'C:\\Users\\hedio\\Documents\\Stage\\src\\feature_extractor\\'
json_beginning = 'nvdcve-1.1-'
json_end = '.json'

# columns for the cve feature vector
features_cols = ['cve_id', 'vendor_name', 'product_name', 'cwe_value', 'cluster', 'description']

exploited_cves_path = path_nvd+"known_exploited_vulnerabilities.json"

csv_url = path_featureExtractor + "cve_feature_vectors.csv"

cve_without_cvss_url = path_featureExtractor + "cve_without_cvss.txt"
cve_rejects = path_featureExtractor + "cve_rejects.txt"