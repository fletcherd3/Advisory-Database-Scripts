import json
from os import path
from helpers import getListOfFiles
from vulnerability import Vulnerability

file_path = path.join(*'data/advisory-database/advisories/github-reviewed'.split('/'))
files = getListOfFiles(file_path)

vulnerabilities = []
affected_packages = set()

for file in files:
    f = open(file, 'r', encoding='utf-8')
    json_data = json.load(f)
    if len(json_data['affected']):
        new_vulnerability = Vulnerability(json_data)
        vulnerabilities.append(new_vulnerability)
        affected_packages.add(new_vulnerability.package)
        if new_vulnerability.package.manager == 'npm':
            print(new_vulnerability.package.name)
            print(new_vulnerability.package.dependants)
            print("--------------")
        # print(new_vulnerability)

# list_affected_packages = list(dict.fromkeys(affected_packages))
# for i in range(len(list_affected_packages)):
#     print(list_affected_packages[i])
