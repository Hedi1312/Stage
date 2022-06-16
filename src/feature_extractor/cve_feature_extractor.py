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

      if os.path.exists(consts.csv_url_pc):
         os.remove(consts.csv_url_pc)

      if os.path.exists(consts.csv_url_sc):
         os.remove(consts.csv_url_sc)

      with open(consts.csv_url, 'a+', encoding="utf8") as csv_file:
         csv_file.write(','.join(consts.features_cols) + "\n")

      with open(consts.csv_url_pc, 'a+', encoding="utf8") as csv_file_pc:
         csv_file_pc.write(','.join(consts.features_cols_pc) + "\n")

      with open(consts.csv_url_sc, 'a+', encoding="utf8") as csv_file_sc:
         csv_file_sc.write(','.join(consts.features_cols_sc) + "\n")

      for year in range(2010, 2023):
         feature_vectors, feature_vectors_pc, feature_vectors_sc = self.extract_features(year)

         with open(consts.csv_url, 'a+', encoding="utf8") as csv_file:
            for vector in feature_vectors:
               csv_file.write(vector.getCsvLine() + "\n")

         with open(consts.csv_url_pc, 'a+', encoding="utf8") as csv_file_pc:
            for vector in feature_vectors_pc:
               csv_file_pc.write(vector.getCsvLine() + "\n")

         with open(consts.csv_url_sc, 'a+', encoding="utf8") as csv_file_sc:
            for vector in feature_vectors_sc:
               csv_file_sc.write(vector.getCsvLine() + "\n")

      return None


   def extract_features(self, year):
      with open('../../data/word_more_frequent.csv') as word_more_frequent:
         datafile_word_more_frequent = word_more_frequent.readlines()
      word_more_frequent.close()

      word_more_frequent = []

      for i in datafile_word_more_frequent:
         word_more_frequent.append(i.rstrip())

      # returns the features vectors for all CVEs of a specific year
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
      features_vectors_pc = []
      features_vectors_sc = []

      # import json
      cve_path = consts.path_nvd + consts.json_beginning + str(year) + consts.json_end

      with open(cve_path, 'r', encoding="utf8") as jsonfile:
         cve_list = json.load(jsonfile)

      cves = cve_list['CVE_Items']
      cwe_non_present = []

      for cve in cves:
         #cve id
         cve_id = cve['cve']['CVE_data_meta']['ID']

         # # Label
         # with open('../../data/data.csv') as data:
         #    datafiledata = data.readlines()
         # data.close()
         #
         # for d in datafiledata:
         #    if cve_id in d:
         #       if len(d.split(',')[1].rstrip()) == 1:
         #          label = "Iot"
         #          break
         #       else:
         #          label = "No_Iot"
         #          break
         #    else:
         #       label = "no_data"

         # vendor name
         nodes = cve['configurations']['nodes']
         vendor_tab = []
         product_tab = []
         label_tab = []


         for node in nodes:
            children = node['children']
            cpe_match2 = node['cpe_match']

            for config in children:
               cpe_match = config['cpe_match']
               for c in cpe_match:
                  cpe23Uri = c['cpe23Uri']
                  if cpe23Uri.split(':')[2] not in label_tab:
                     label1 = cpe23Uri.split(':')[2]
                     label_tab.append(label1.replace(",", ""))

                  if cpe23Uri.split(':')[3] not in vendor_tab:
                     cpe = cpe23Uri.split(':')[3]
                     cpe = cpe.replace(",", "")
                     cpe = cpe.replace('\\"',"")
                     cpe = cpe.replace('“', "")
                     vendor_tab.append(cpe.replace("\\'", ""))

                  if cpe23Uri.split(':')[4] not in product_tab:
                     product = cpe23Uri.split(':')[4]
                     product = product.replace(",", "")
                     product = product.replace('\\"',"")
                     product = product.replace('“', "")
                     product_tab.append(product.replace("\\'", ""))

            for config2 in cpe_match2:
               cpe23Uri2 = config2['cpe23Uri']
               if cpe23Uri2.split(':')[2] not in label_tab:
                  label2 = cpe23Uri2.split(':')[2]
                  label_tab.append(label2.replace(",", ""))

               if cpe23Uri2.split(':')[3] not in vendor_tab:
                  cpe2 = cpe23Uri2.split(':')[3]
                  cpe2 = cpe2.replace(",", "")
                  cpe2 = cpe2.replace('\\"',"")
                  cpe2 = cpe2.replace('“', "")
                  vendor_tab.append(cpe2.replace("\\'", ""))

               if cpe23Uri2.split(':')[4] not in product_tab:
                  product2 = cpe23Uri2.split(':')[4]
                  product2 = product2.replace(",", "")
                  product2 = product2.replace('\\"',"")
                  product2 = product2.replace('“', "")
                  product_tab.append(product2.replace("\\'", ""))

            vendor_name = ":".join(vendor_tab)
            product_name = ":".join(product_tab)

         # Label
         if not label_tab:
            label = "no_data"
         else:
            for lab in label_tab:
               if "h" in lab:
                  label = "iot"
               else:
                  label = "non_iot"



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
         if cwe_value == "NVD-CWE-noinfo" or cwe_value == "NVD-CWE-Other" or cwe_value == "CWE-254" or cwe_value =="CWE-199" or cwe_value =="CWE-216" or cwe_value =="CWE-1278":
            continue

         # Description
         summary = cve['cve']['description']['description_data'][0]['value']
         if summary.startswith('**'):
            special_message = summary.split('**')[1].strip()
            if special_message in to_ignore:
               continue
            elif special_message in when_assigned:
               unsupported_when_assigned = 1

         clean_summary = self.get_clean_summary(summary)
         clean_summary = clean_summary.replace('“', "")
         clean_summary = clean_summary.replace('”', "")
         # One_hot_encoding
         one_hot_encoding =''
         for w in word_more_frequent:
            if w in clean_summary:
               one_hot_encoding = one_hot_encoding + str(1) + '-'
            else:
               one_hot_encoding = one_hot_encoding + str(0) + '-'

         # Cluster
         with open('../../data/arbre.txt') as arbre:
            datafile = arbre.readlines()
         arbre.close()

         with open('../../data/liste_not_in_arbre.csv') as not_in_arbre:
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
                  m = self.find_primary_cluster(line)

               if "Secondary Cluster" in line:
                  cluster = n + '-' + m + '-' + n
                  prim_cluster = m
                  sec_cluster = n

               else:
                  x = self.find_secondary_cluster(line)
                  cluster = n + '-' + x + '-' + m
                  prim_cluster = m
                  sec_cluster = x

               if cve_id + ':' + cluster not in clusters:
                  clusters.append(cve_id + ':' + cluster)
                  prim_clusters.append(prim_cluster)
                  prim_clusters = ",".join(prim_clusters)

                  sec_clusters.append(sec_cluster)
                  sec_clusters = ",".join(sec_clusters)

                  clusters_final.append(cluster)
                  clusters_final = ",".join(clusters_final)

               else:
                  cwe_double.append(cve_id + ':' + cluster)

            else:
               for l in datafile_not_in_arbre:
                  if "CWE-"+cwe_value_split == l.split(",")[0]:
                     prim_cluster = l.split(",")[1].split("-")[1]
                     sec_cluster = l.split(",")[2].split("-")[1].split("\n")[0]
                     cluster = cwe_value_split + "-" + sec_cluster + "-" + prim_cluster

                     if cve_id + ':' + cluster not in clusters:
                        clusters.append(cve_id + ':' + cluster)
                        prim_clusters.append(prim_cluster)
                        prim_clusters = ",".join(prim_clusters)

                        sec_clusters.append(sec_cluster)
                        sec_clusters = ",".join(sec_clusters)

                        clusters_final.append(cluster)
                        clusters_final = ",".join(clusters_final)

                     else:
                        cwe_double.append(cve_id + ':' + cluster)

         # preparing the features vector

         cve_dict = {'cve_id': cve_id,
                     'vendor_name': vendor_name,
                     'product_name': product_name,
                     'cwe_value': cwe_value,
                     'one_hot_encoding': one_hot_encoding.rstrip('-'),
                     'label' : label
                     }
         
         features_vectors.append(Cve_Feature_Vector(cve_dict))

         cve_dict_pc = {'cve_id': cve_id,
                     'vendor_name': vendor_name,
                     'product_name': product_name,
                     'primary_cluster': prim_clusters,
                     'one_hot_encoding': one_hot_encoding.rstrip('-'),
                     'label' : label
                     }

         features_vectors_pc.append(Cve_Feature_Vector(cve_dict_pc))

         cve_dict_sc = {'cve_id': cve_id,
                     'vendor_name': vendor_name,
                     'product_name': product_name,
                     'secondary_cluster': sec_clusters,
                     'one_hot_encoding': one_hot_encoding.rstrip('-'),
                     'label' : label
                     }

         features_vectors_sc.append(Cve_Feature_Vector(cve_dict_sc))

      return features_vectors, features_vectors_pc, features_vectors_sc


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

   