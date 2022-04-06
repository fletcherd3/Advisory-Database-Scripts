import json
from os import path

import constraint
from helpers import get_list_of_files
from vulnerability import Vulnerability
from datetime import datetime

file_path = path.join(*'data/advisory-database/advisories/github-reviewed'.split('/'))
files = get_list_of_files(file_path)

vulnerabilities = []
count = 0

print("Started at {0}".format(datetime.now()))

for file in files:
    f = open(file, 'r', encoding='utf-8')
    json_data = json.load(f)
    if len(json_data['affected']):
        count += 1
        print(count)
        vulnerabilities.append(Vulnerability(json_data))


print("Finished at {0}".format(datetime.now()))


print(len(vulnerabilities)) 
for v in vulnerabilities:
    print("Vulnerability Name:", v.package)
    print("Affected Versions:", v.affected_versions)

    for _, row in v.dependents.iterrows():
        print(row["Project"], row["Version"], constraint.check_affected_versions(v.affected_versions, row["Constraint"]))


# for i in range(10):
#     f = open(files[i], 'r', encoding='utf-8')
#     json_data = json.load(f)
#     if len(json_data['affected']):
#         vulnerabilities.append(Vulnerability(json_data))
