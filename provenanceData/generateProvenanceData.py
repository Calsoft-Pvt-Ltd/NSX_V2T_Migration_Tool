import json
import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

PWD = os.getcwd()
REQUIREMENTS_FILE = os.path.join(PWD, 'src', 'requirements.txt')
PROV_DATA_FILE = os.path.join(PWD, 'provenanceData', 'network_provenance_data.json')


def get_packages_path():
    with open(REQUIREMENTS_FILE) as f:
        packages = f.readlines()

    package_paths = []
    for package in packages:
        package_name, package_version = package.strip('\n').split('==')
        response = requests.get(f"https://pypi.org/pypi/{package_name}/json", verify=False)
        response_data = response.json()
        version_info = response_data['releases'][package_version]

        for version_type in version_info:
            if version_type.get('packagetype') == 'sdist':
                package_paths.append(version_type['url'].split('/', 3)[-1])
                break
        else:
            package_paths.append(version_info[0]['url'].split('/', 3)[-1])

    return package_paths


if __name__ == '__main__':
    prov_data = {
      "artifact_repositories": [
        {
          "content": "binary",
          "host": "files.pythonhosted.org",
          "protocol": "https",
          "paths": get_packages_path()
        }
      ]
    }

    with open(PROV_DATA_FILE, 'w') as prov_file:
        json.dump(prov_data, prov_file, indent=2)
