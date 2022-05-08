import string
import pandas as pd
import json
import sys
import os
import re
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


      with open(consts.csv_url, 'a+', encoding="utf8") as csv_file:
         csv_file.write(','.join(consts.features_cols) + "\n")

      for year in range(2010, 2023):
         feature_vectors = self.extract_features(year)

         with open(consts.csv_url, 'a+', encoding="utf8") as csv_file:
            
            for vector in feature_vectors:
               csv_file.write(vector.getCsvLine() + "\n")

      return None



   def extract_features(self, year):

      # returns the features vectors for all CVEs of a specific year

      global cluster
      to_ignore = ('REJECT', 'DISPUTED', 'Resolved')
      when_assigned = ('UNSUPPORTED WHEN ASSIGNED', 'PRODUCT NOT SUPPORTED WHEN ASSIGNED', 'VERSION NOT SUPPORTED WHEN ASSIGNED')

      # list of exploited CVEs
      with open(consts.exploited_cves_path, 'r', encoding="utf8") as jsonfile:
         exploited_cves = json.load(jsonfile)
      
      exploited_cves_ids = []
      for expl in exploited_cves['vulnerabilities']:
         exploited_cves_ids.append(expl['cveID'])

      # feature vectors for cves of the year
      features_vectors = []

      # import json
      cve_path = consts.path_nvd + consts.json_beginning + str(year) + consts.json_end

      with open(cve_path, 'r', encoding="utf8") as jsonfile:
         cve_list = json.load(jsonfile)

      cves = cve_list['CVE_Items']
      cwe_non_present = []

      for cve in cves:

         #cve id
         cve_id = cve['cve']['CVE_data_meta']['ID']

         # vendor name
         nodes = cve['configurations']['nodes']
         vendor_tab = []
         product_tab = []

         for node in nodes:
            children = node['children']
            cpe_match2 = node['cpe_match']

            for config in children:
               cpe_match = config['cpe_match']
               for c in cpe_match:
                  cpe23Uri = c['cpe23Uri']
                  if cpe23Uri.split(':')[3] not in vendor_tab:
                     cpe = cpe23Uri.split(':')[3]
                     vendor_tab.append(cpe.replace(",", ""))

                  if cpe23Uri.split(':')[4] not in product_tab:
                     product = cpe23Uri.split(':')[4]
                     product_tab.append(product.replace(",", ""))

            for config2 in cpe_match2:

               cpe23Uri2 = config2['cpe23Uri']
               if cpe23Uri2.split(':')[3] not in vendor_tab:
                  cpe2 = cpe23Uri2.split(':')[3]
                  vendor_tab.append(cpe2.replace(",", ""))

               if cpe23Uri2.split(':')[4] not in product_tab:
                  product2 = cpe23Uri2.split(':')[4]
                  product_tab.append(product2.replace(",", ""))

            vendor_name = ":".join(vendor_tab)
            product_name = ":".join(product_tab)


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
            cwe_value_split = cwe_value.split("-")[1]
         else:
            continue
         
         if cwe_value == "NVD-CWE-noinfo":
            continue


         # Cluster
         with open('../../data/arbre.txt') as arbre:
            datafile = arbre.readlines()


         cwe_non_present.append(cwe_value_split)

         clusters = []
         clusters_final = []
         cwe_double = []
         for line in datafile:
            if '(' + cwe_value_split + ')' in line:
               if cwe_value_split in cwe_non_present:
                  cwe_non_present.remove(cwe_value_split)
               l = line

               n = cwe_value_split

               if "Primary Cluster" in l:
                  cluster = n + '-' + n + '-' + n
               else:
                  m = self.find_primary_cluster(l)

               if "Secondary Cluster" in l:
                  cluster = n + '-' + m + '-' + n

               else:
                  x = self.find_secondary_cluster(l)
                  cluster = n + '-' + x + '-' + m

               if cve_id + ':' + cluster not in clusters:
                  clusters.append(cve_id + ':' + cluster)
                  clusters_final.append(cluster)
               else:
                  cwe_double.append(cve_id + ':' + cluster)


         # summary
         summary = cve['cve']['description']['description_data'][0]['value']


         if summary.startswith('**'):
            special_message = summary.split('**')[1].strip()

            if special_message in to_ignore:
               continue
            elif special_message in when_assigned:
               unsupported_when_assigned = 1
         
         clean_summary = self.get_clean_summary(summary)


         # preparing the features vector

         cve_dict = {'cve_id': cve_id,
                     'vendor_name': vendor_name,
                     'product_name': product_name,
                     'cwe_value': cwe_value,
                     'cluster': clusters_final,
                     'description': clean_summary
                     }
         
         features_vectors.append(Cve_Feature_Vector(cve_dict))

      return features_vectors


   def find_primary_cluster(self, l):
      global primary_cluster

      with open('../../data/arbre.txt') as arbre:
         datafile = arbre.readlines()
         arbre.close()

         primary = []
         good_primary_cluster = []

         for i, line in enumerate(datafile, 1):
            if l in line:
               num_line_l = i

            if "Primary Cluster" in line:
               primary.append(str(i) + line)

         for p in primary:
            num_line_m = p.split("-")[0]

            if int(num_line_m) < num_line_l:
               good_primary_cluster.append(p)

         primary_cluster = str(good_primary_cluster[-1])
         primary_cluster = re.findall(r"\(\s*\+?(-?\d+)\s*\)", primary_cluster)
         primary_cluster = str(primary_cluster)
         primary_cluster = primary_cluster.split("'")[1]

         return primary_cluster


   def find_secondary_cluster(self, l):
      global secondary_cluster

      good_secondary_cluster = []
      m = self.find_primary_cluster(l)
      m = str('(' + m + ')')

      n = re.findall(r"\(\s*\+?(-?\d+)\s*\)", l)
      n = str(n)
      n = n.split("'")[1]
      n = str('(' + n + ')')

      with open('../../data/arbre.txt') as arbre:
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
               secondarys.append(str(i) + line)

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

   