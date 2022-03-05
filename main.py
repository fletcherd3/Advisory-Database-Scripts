import json
from os import path
from helpers import get_list_of_files
from vulnerability import Vulnerability
from datetime import datetime

file_path = path.join(*'data/advisory-database/advisories/github-reviewed'.split('/'))
files = get_list_of_files(file_path)

vulnerabilities = []

print("Started at {0}".format(datetime.now()))

for file in files:
    f = open(file, 'r', encoding='utf-8')
    json_data = json.load(f)
    if len(json_data['affected']):
        vulnerabilities.append(Vulnerability(json_data))

print("Finished at {0}".format(datetime.now()))
print(len(vulnerabilities))

# for i in range(10):
#     f = open(files[i], 'r', encoding='utf-8')
#     json_data = json.load(f)
#     if len(json_data['affected']):
#         vulnerabilities.append(Vulnerability(json_data))
