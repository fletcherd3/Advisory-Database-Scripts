import json
import csv
from os import path
from helpers import get_list_of_files
from severity import Severity


def valid_vulnerability(data):
    return len(data['affected']) > 0 and not withdrawn(data)


def withdrawn(data):
    return 'withdrawn' in data


def get_new_affected_packages(data, packages):
    for package in data['affected']:
        package_name = package['package']['name']
        year_vulnerable = get_year_discovered(data)
        if package_name in packages.keys():
            if year_vulnerable in packages[package_name].keys():
                new_severity = get_severity(data, packages[package_name][year_vulnerable])
            else:
                new_severity = get_severity(data)
            packages[package_name][year_vulnerable] = new_severity
        else:
            packages[package_name] = dict()
            packages[package_name][year_vulnerable] = get_severity(data)
    return packages


def get_year_discovered(data):
    if len(data['aliases']) > 0:
        return data['aliases'][0].split('-')[1]
    return data['published'].split('-')[0]


def get_severity(data, current_severity=Severity.LOW.name):
    data_severity = data['database_specific']['severity']
    if Severity[data_severity].value > Severity[current_severity].value:
        return Severity[data_severity].name
    return current_severity


file_path = path.join(*'data/advisory-database/advisories/github-reviewed'.split('/'))
files = get_list_of_files(file_path)

output_file = open("output.csv", "w", newline='')
writer = csv.writer(output_file)

output_data = dict()
affected_packages = dict()

for file in files:
    input_file = open(file, 'r', encoding='utf-8')
    vulnerability = json.load(input_file)
    if valid_vulnerability(vulnerability):
        affected_packages = get_new_affected_packages(vulnerability, affected_packages)

for affected_package in affected_packages.values():
    for year_discovered, severity in affected_package.items():
        if year_discovered in output_data:
            if severity in output_data[year_discovered]:
                output_data[year_discovered][severity] += 1
            else:
                output_data[year_discovered][severity] = 1
        else:
            output_data[year_discovered] = {'LOW': 0, 'MODERATE': 0, 'HIGH': 0, 'CRITICAL': 0}
            output_data[year_discovered][severity] = 1


for year, severities in output_data.items():
    row = [year]
    for severity in severities:
        row.append(severities[severity])
    writer.writerow(row)

output_file.close()
