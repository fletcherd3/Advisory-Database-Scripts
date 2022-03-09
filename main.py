import json
import csv
from os import path
from helpers import get_list_of_files


def valid_vulnerability(data):
    return len(data['affected']) > 0 and not withdrawn(data)


def withdrawn(data):
    return 'withdrawn' in data


def get_new_affected_packages(data, packages):
    for package in data['affected']:
        package_name = package['package']['name']
        year_vulnerable = get_year_discovered(data)
        if package_name not in packages.keys():
            packages[package_name] = dict()
        packages[package_name][year_vulnerable] = package['package']['ecosystem']
    return packages


def get_year_discovered(data):
    if len(data['aliases']) > 0:
        return data['aliases'][0].split('-')[1]
    return data['published'].split('-')[0]


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
    for year_discovered, package_manager in affected_package.items():
        if year_discovered in output_data:
            if package_manager in output_data[year_discovered]:
                output_data[year_discovered][package_manager] += 1
            else:
                output_data[year_discovered][package_manager] = 1
        else:
            output_data[year_discovered] = {'RubyGems': 0, 'npm': 0, 'PyPI': 0, 'Maven': 0, 'NuGet': 0, 'Packagist': 0,
                                            'Go': 0, 'crates.io': 0}
            output_data[year_discovered][package_manager] = 1


for year, package_manager in output_data.items():
    row = [year]
    for manager in package_manager:
        row.append(package_manager[manager])
    writer.writerow(row)

output_file.close()
