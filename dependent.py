import os
import dask.dataframe
import pandas


# Github Advisory Database to Libraries.io package manager mapping
PACKAGE_MANAGER = {
    'RubyGems': 'Rubygems',
    'npm': 'NPM',
    'PyPI': 'Pypi',
    'Maven': 'Maven',
    'NuGet': 'NuGet',
    'Packagist': 'Packagist',
    'Go': 'Go',
    'crates.io': 'Cargo'
}

INPUT_PATH = 'data/'

REQUIRED_COLS = ["Project", "Constraint", "Dependency ID"]


# print("Opening Dependancy Data")
# data = dask.dataframe.read_csv(os.path.join(INPUT_PATH, 'libio-dependencies.csv'), header=0, dtype={'Project': 'str'}, usecols=REQUIRED_COLS)
# data.set_index("EC")
# data = data.persist()
# print("Done")


def set_dependents(package_id):
    print(package_id)
    df = data[data["Dependency ID"] == float(int(package_id))]
    result = df[["Project", "Constraint"]]
    result = result.compute()
    print(result)

class Dependent:
    def __init__(self, package_info):
        self.name = package_info['name']
        self.manager = package_info['platform']
        self.affected_versions = []  # self.set_affected_versions(package_info)
        self.patched_versions = []  # self.set_patched_versions(package_info)
        self.dependents = []  # set_dependents(self.name, self.manager)  # indirect/transitive dependencies

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
