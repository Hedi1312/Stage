import string
import pandas as pd
import json
import sys
import os
import nltk
from gensim.parsing.preprocessing import remove_stopwords, STOPWORDS
import consts
import datetime
from cve_feature_vector import Cve_Feature_Vector

sno = nltk.stem.SnowballStemmer('english')

stopwords_list = [word for word in STOPWORDS]
stopwords_list.append("instead")


class Cve_Feature_Extractor:

   def feature_vectors_to_csv(self):

      if os.path.exists(consts.csv_url):
         os.remove(consts.csv_url)
      
      with open(consts.csv_url, 'a+',encoding="utf8") as csv_file:
         csv_file.write(','.join(consts.features_cols) + "\n")

      for year in range(2013,2023):
         feature_vectors = self.extract_features(year)

         with open(consts.csv_url, 'a+',encoding="utf8") as csv_file:
            
            for vector in feature_vectors:
               csv_file.write(vector.getCsvLine() + "\n")

      return None


         



   def extract_features(self, year):

      # returns the features vectors for all CVEs of a specific year

      to_ignore = ('REJECT', 'DISPUTED', 'Resolved')
      when_assigned = ('UNSUPPORTED WHEN ASSIGNED', 'PRODUCT NOT SUPPORTED WHEN ASSIGNED', 'VERSION NOT SUPPORTED WHEN ASSIGNED')

      # list of exploited CVEs
      with open(consts.exploited_cves_path, 'r',encoding="utf8") as jsonfile:
         exploited_cves = json.load(jsonfile)
      
      exploited_cves_ids = []
      for expl in exploited_cves['vulnerabilities']:
         exploited_cves_ids.append(expl['cveID'])

      # feature vectors for cves of the year
      features_vectors = []

      # import json
      cve_path = consts.path_nvd + consts.json_beginning + str(year) + consts.json_end

      with open(cve_path, 'r',encoding="utf8") as jsonfile:
         cve_list = json.load(jsonfile)

      cves = cve_list['CVE_Items']

      for cve in cves:

         #cve id
         cve_id = cve['cve']['CVE_data_meta']['ID']

         # check if cvss score exists
         if (len(cve['impact'])>0):
            if 'baseMetricV3' in cve['impact'].keys():
               cvss = cve['impact']['baseMetricV3']['cvssV3']['baseScore']
            else:
               continue
         else:
            continue
      
         # cwe value
         cwe = cve['cve']['problemtype']['problemtype_data'][0]['description']
         if (len(cwe)>0):
            cwe_value = cwe[0]['value']
         else:
            continue
         
         if cwe_value == "NVD-CWE-noinfo":
            continue

         # references
         reference_data = cve['cve']['references']['reference_data']

         # count references
         ref_count = len(reference_data)

         # proof of concept ?
         poc = 0

         if (ref_count>0):
            for ref in reference_data:
               if "tags" in ref.keys():
                  if "Exploit" in ref['tags']:
                     poc = 1
                     break

         # vulnerable configurations and products
         nodes = cve['configurations']['nodes']
         vuln_configs = 0
         products = set()
      
         for node in nodes:
            cpe_match = node['cpe_match']

            for config in cpe_match:
                  vuln_configs += 1

                  cpe23Uri = config['cpe23Uri']
                  products.add(cpe23Uri.split(':')[3])
         
         vuln_products = len(products)

         publishedDate = datetime.datetime.strptime(cve['publishedDate'][:10], "%Y-%m-%d")
         lastModifiedDate = datetime.datetime.strptime(cve['lastModifiedDate'][:10], "%Y-%m-%d")

         days_diff = (lastModifiedDate.date() - publishedDate.date()).days

         # summary
         summary = cve['cve']['description']['description_data'][0]['value']

         unsupported_when_assigned = 0

         if summary.startswith('**'):
            special_message = summary.split('**')[1].strip()

            if special_message in to_ignore:
               continue
            elif special_message in when_assigned:
               unsupported_when_assigned = 1
         
         clean_summary = self.get_clean_summary(summary)

         # exploited or not?

         class_exploited=0

         if cve_id in exploited_cves_ids:
            class_exploited=1

         # preparing the features vector

         cve_dict = {'cve_id':cve_id, 
                     'cvss':cvss, 
                     'cwe_value':cwe_value,
                     'vul_conf_count':vuln_configs, 
                     'vul_products':vuln_products, 
                     'days_diff':days_diff, 
                     'ref_count':ref_count, 
                     'clean_summary':clean_summary,
                     'unsupported_when_assigned':unsupported_when_assigned,
                     'class_exploited':class_exploited,
                     'proof_of_concept':poc
                     }
         
         features_vectors.append(Cve_Feature_Vector(cve_dict))

      return features_vectors


      
   def get_clean_summary(self, summary):
      # to lower
      summary = summary.lower()

      # remove punctuation
      summary = summary.translate(str.maketrans('', '', string.punctuation))

      summary_words = summary.split(" ")

      # remove stopwords
      summary_words = [word for word in summary_words if word not in stopwords_list]

      # stemming
      clean_summary_set = set()

      for word in summary_words:
         clean_summary_set.add(sno.stem(word))

      # remove numbers
      clean_summary_set = set(map(lambda x: str(x), clean_summary_set))

      clean_summary_final = set(word for word in clean_summary_set if not word.isdigit())

      return ' '.join(clean_summary_final)

   