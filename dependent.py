import os
from dotenv import load_dotenv
import requests
import json
import time

load_dotenv()

API_KEY = os.getenv('API_KEY')

# Github Advisory Database to Libraries.io package manager mapping
PACKAGE_MANAGER = {
    'RubyGems': 'Rubygems',
    'npm': 'NPM',
    'PyPi': 'Pypi',
    'Maven': 'Maven',
    'NuGet': 'NuGet',
    'Packagist': 'Packagist',
    'Go': 'Go',
    'crates.io': 'Cargo'
}


def set_dependents(package_name, package_manager):
    time.sleep(1)  # API has a request limit, so have to delay in between requests
    res = requests.get('https://libraries.io/api/{0}/{1}/dependents?api_key={2}'.format(package_manager, package_name, API_KEY))
    response = json.loads(res.text)
    dependents = []
    for dependent in response:
        dependents.append(Dependent(dependent))
    return dependents


# def set_patched_versions(data):
#     patched_versions = []
#     for i in range(len(data['affected'])):
#         patched_versions.append(add_patched_version(data, i))
#     return patched_versions
#
#
# def add_patched_version(data, i):
#     if len(data['affected'][i]['ranges'][0]['events']) == 2:
#         return data['affected'][i]['ranges'][0]['events'][1]['fixed']
#     return 'None'
#
#
# def set_affected_versions(data):
#     affected_versions = []
#     for i in range(len(data['affected'])):
#         affected_versions.append(data['affected'][i]['ranges'][0]['events'][0]['introduced'])
#     return affected_versions


class Dependent:
    def __init__(self, package_info):
        self.name = package_info['name']
        self.manager = package_info['platform']
        self.affected_versions = []  # self.set_affected_versions(package_info)
        self.patched_versions = []  # self.set_patched_versions(package_info)
        self.dependents = []  # set_dependents(self.name, self.manager)

    def __str__(self):
        return "---------------------------------------------------\n" \
               "Package {0}:\n" \
               "Package Manager: {1}\n" \
               "Affected Versions: {2}\n" \
               "Patched Versions: {3}\n" \
               "Dependents: {4}\n" \
               "---------------------------------------------------\n".format(self.name, self.manager,
                                                                              self.affected_versions,
                                                                              self.patched_versions, self.dependents)
