
import os
import json
import requests
import base64
import csv
import parsing_git_commits
from urllib.parse import urlparse

access_token = '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'

#Set up headers with the access token
headers = {
    'Authorization': f'token {access_token}',
    'Accept': 'application/vnd.github.v3+json'
}

def get_cargo_toml_content(owner, repo):
    # url = f'https://crates.io/api/v1/crates?q={cargo_package_name}'
    # response = requests.get(url, headers={'User-Agent': 'esinyavin01@gmail.com'})
    # return response.json()
    url = f'https://api.github.com/repos/{owner}/{repo}/contents/Cargo.toml'
    response = requests.get(url, headers=headers)
    content = response.json()['content']
    return base64.b64decode(content).decode('utf-8')

def get_github_link_and_categories(repo_name):
    url = f'https://crates.io/api/v1/crates/{repo_name}'
    response = requests.get(url, headers={'User-Agent':'esinyavin01@gmail.com'})
    if response.status_code == 200:
        res = {}
        if 'crate' in response.json():
            if 'repository' in response.json()['crate']:
                res['github_link'] = response.json()['crate']['repository']
            else:
                return "No github link for repo {repo_name}"
            if 'categories' in response.json()['crate']:
                res['categories'] = response.json()['crate']['categories']
            return res
        else: 
            print("Failed finding github link/categories for repo {repo_name}") 
            return None
    else:
        print(f"Error: {response.status_code} - {response.text} - {url}")
        return None

def get_dependents(cargo_package_name):
    url = f'https://crates.io/api/v1/crates/{cargo_package_name}/reverse_dependencies'
    response = requests.get(url, headers={'User-Agent':'esinyavin01@gmail.com'})
    if response.status_code == 200:
        result = {}
        for version in response.json()['versions']:
            info_about_dependent = get_github_link_and_categories(version['crate'])
            result[version['crate']] = {'downloads':version['downloads'], 
                                        'github_url': info_about_dependent['github_link'] if 'github_link' in info_about_dependent else "", 
                                        'categories': info_about_dependent['categories'] if 'categories' in info_about_dependent else "",
                                        'version':version['num']}
        return result
    else:
        return "Failed finding dependents"
    
#get minimum version of dependency that can be used (basically ignore ~ and ^). 
def get_version_of_dependency(dependent, version, dependency):
    url = f'https://crates.io/api/v1/crates/{dependent}/{version}/dependencies'
    response = requests.get(url, headers={'User-Agent':'esinyavin01@gmail.com'})
    if response.status_code == 200:
        for dep in response.json()["dependencies"]:
            if dep['crate_id'] == dependency:
                # if '~' in dep['req']:
                #     print('~ in req for dependent ' + dependent + ' and dependency ' + dependency)
                # return dep['req'].replace('^', '')
                return dep['req'].replace('^', '').replace('~', '')
        return "Failed finding dependency version"
    else:
        return "Failed finding dependency version"
    
# def get_latest_version(dependent):
#     url = f'https://crates.io/api/v1/crates/{dependent}'
#     response = requests.get(url, headers={'User-Agent':'esinyavin01@gmail.com'})
#     if response.status_code == 200:
#         for dep in response.json()["dependencies"]:
#             if dep['crate_id'] == dependency:
#                 return dep['req'].replace('^', '').replace('~', '')
#     else:
#         return "Failed finding dependency version"
    
def json_to_row(file_path: str):
    with open(file_path, 'r') as file:
        data = json.load(file)
    
    res = []
    if "withdrawn" in data or 'affected' not in data:
        return res
    
    for affected in data["affected"]:
        #filter out for not crates.io
        
        if not affected["package"] or not affected["package"]["ecosystem"] or affected["package"]["ecosystem"] != "crates.io":
            return
        
        row = []
        row.append(data["id"])
        row.append(data["published"])
        name = affected["package"]["name"]
        row.append(name)

        owner = ""
        repo = ""

        found_github = False
        github_url = ""
        for reference in data["references"]:
            prefix = "https://github.com/"
            if prefix in reference["url"]:
                new_string = reference["url"][len(prefix):]
                owner = new_string[:new_string.find('/')]
                row.append(owner)
                new_string_2 = new_string[new_string.find('/')+1:]
                repo = new_string_2[:new_string_2.find('/')]
                row.append(repo)
                found_github = True
                github_url = reference["url"]
        if found_github == False:
            row.append("")
            row.append("")
        
        row.append(affected["package"]["purl"])

        if len(data["severity"]) > 0:
            row.append(data["severity"])
        else:
            row.append([])

        if affected["database_specific"] and affected["database_specific"]["categories"]:
            row.append(affected["database_specific"]["categories"])
        else:
            row.append([])

        #get categories and github url

        info = get_github_link_and_categories(name)
        if info == None:
            row.append([])
            row.append("")
        else:
            if 'categories' in info:
                row.append(info['categories'])
            else:
                row.append([])

            if 'github_link' in info:
                #if info['github_link'] != github_url:
                    # print("Error: github url mismatch")
                    # print(github_url)
                    # print(info['github_link'])
                #use the one gotten from api call
                row.append(info['github_link'])
            else:
                #use the one parsed from above
                row.append(github_url)
        
        if len(affected["ranges"]) > 1:
            print("len(affected[\"ranges\"]) > 1")

        introduced = ""
        fixed = ""

        if affected["ranges"] and affected["ranges"][0]["events"] and affected["ranges"][0]["events"]:
            for event in affected["ranges"][0]["events"]:
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
            
        row.append(introduced)
        row.append(fixed)

        if fixed != "":
            date_patched = parsing_git_commits.get_date_of_patch(owner, repo, fixed)
        else:
            date_patched = ''
        
        row.append(date_patched)

        #get dependents using crates.io API
        #limitations: only current ones, not historical, must have cargo.toml
        dependents = get_dependents(name)
        row.append(dependents)
        res.append(row)
    
    return res

def get_date_created(repo_name):
    url = f'https://crates.io/api/v1/crates/{repo_name}'
    response = requests.get(url, headers={'User-Agent':'esinyavin01@gmail.com'})
    if response.status_code == 200:
        if 'crate' in response.json():
            if 'created_at' in response.json()['crate']:
                return response.json()['crate']['created_at']
            print("Failed finding created_at for repo {repo_name}") 
            return None
        else: 
            print("Failed finding created_at for repo {repo_name}") 
            return None
    else:
        print(f"Error: {response.status_code} - {response.text} - {url}")
        return None


def process_rustsec_jsons():
    # Folder containing RustSec advisories in the OSV format
    folder_path = './advisory-db-osv/crates/'
    # Read in all vulnerabilities
    first_row = ["id", "published", "name", "gh_owner", "gh_repo", "purl", "severity", "categories_vuln", "categories_package", "github_link", "introduced_version", "patched_version", "date_of_patch", "dependents"]

    with open('all_vulns_info5.cvs', 'r', newline='') as csv_file2:
        csv_reader = csv.reader(csv_file2)
        all_collected = []
        first = True
        for row in csv_reader:
            if first:
                first = False
                continue
            all_collected.append(row[0])
        

    with open('all_vulns_info5.cvs', 'a', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        #csv_writer.writerow(first_row)


        #skip = True
        for filename in os.listdir(folder_path):
            if filename.endswith('.json'):
                #if filename == 'RUSTSEC-2021-0098.json':
                #    skip = False
                #    continue
                
                #if skip:
                #    continue
                if filename[:-len('.json')] in all_collected:
                    print('already_parsed')
                    continue

                # Construct the full path to the JSON file
                file_path = os.path.join(folder_path, filename)
                # Read the JSON file into a DataFrame
                osv = json_to_row(file_path)
                if osv is not None:
                    for o in osv:
                        print(o)
                    csv_writer.writerows(osv)
    
def get_dependent_patch_info():
    already_seen = []
    with open('dependent_patch_info.cvs', 'r', newline='') as csv_file2:
        reader = csv.reader(csv_file2)
        first = True
        for row in reader:
            if first:
                first = False
                continue
            already_seen.append(row[0])

    with open('dependent_patch_info.cvs', 'a', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        #first_row = ["vuln_id", "vuln_package_name", "dependent_name", "dependent_info"]
        #csv_writer.writerow(first_row)
        with open('all_vulns_info5.cvs', 'r') as csv_file:
            csv_reader = csv.reader(csv_file)
            first = True
            for row in csv_reader:
                if first:
                    first = False
                    continue
                id = row[0]
                if id in already_seen:
                    print("duplicate")
                    continue
                package_name = row[2]
                patched_version = row[11]
                introduced_version = row[10]
                if introduced_version[-2:] == '-0':
                    introduced_version = introduced_version[:-2]
                
                dependents = []
                if row[13] != None and row[13] != "":
                    try:
                        dependents = json.loads(row[13].replace("\'", "\""))
                    except Exception as e:
                        print(e) 
                        continue
                        
                for dependent in dependents:
                    dependent_on_version = get_version_of_dependency(dependent, dependents[dependent]['version'], package_name)
                    if patched_version == "":
                        #if less than introduced -- this is where tilda and caret matter -- want to get range -- but let's actually just ignore them altogether 
                        if parsing_git_commits.compare_cargo_versions(dependent_on_version, introduced_version) == -1:
                            #dependent on a version that came before the bug was introduced
                            print([id, package_name, dependent, {"dependency_patched":False, "dependent_on_vuln_version":False}])
                            csv_writer.writerow([id, package_name, dependent, {"dependency_patched":False, "dependent_on_vuln_version":False}])
                        else:
                            print([id, package_name, dependent, {"dependency_patched":False,  "dependent_on_vuln_version":True}])
                            csv_writer.writerow([id, package_name, dependent, {"dependency_patched":False,  "dependent_on_vuln_version":True}])
                        continue

                    if parsing_git_commits.compare_cargo_versions(dependent_on_version, introduced_version) == -1:
                        #dependent on a version that came before the bug was introduced
                        print([id, package_name, dependent, {"dependency_patched":True, "dependent_on_vuln_version":False}])
                        csv_writer.writerow([id, package_name, dependent, {"dependency_patched":True, "dependent_on_vuln_version":False}])
                    elif parsing_git_commits.compare_cargo_versions(dependent_on_version, patched_version) == -1:
                        #dependent on a version between introduced and fixed
                        print([id, package_name, dependent, {"dependency_patched":True, "dependent_on_vuln_version":True}])
                        csv_writer.writerow([id, package_name, dependent, {"dependency_patched":True, "dependent_on_vuln_version":True}])
                    else:
                        #crate created after dependency was patched
                        date_created = get_date_created(dependent)
                        #TO DO: replace row[1] with the date received from laura
                        date = row[12] if row[12] != "" and row[12] != None else row[1]
                        if date_created != None and parsing_git_commits.compare_date_strings2(date, date_created) == -1:
                            print([id, package_name, dependent, {"dependency_patched":True, "dependent_on_vuln_version":False, "created_after_patch":True}])
                            csv_writer.writerow([id, package_name, dependent, {"dependency_patched":True, "dependent_on_vuln_version":False, "created_after_patch":True}])
                            continue

                        if dependents[dependent]['github_url'] == '':
                            print([id, package_name, dependent, {"dependency_patched":True, "dependent_on_vuln_version":False, "created_after_patch":False,  "error":"could not get github link"}])
                            csv_writer.writerow([id, package_name, dependent, {"dependency_patched":True, "dependent_on_vuln_version":False, "created_after_patch":False, "error":"could not get github link"}])
                            continue
                        # parsed_url = urlparse(dependents[dependent]['github_url'])
                        # if dependent != parsed_url.path.split("/")[-1]:
                        #     print("github link does not match crate name")
                        #     print(dependent)
                        #     print(parsed_url.path.split("/")[-1])
                        #     csv_writer.writerow([id, package_name, dependent, {"error":"github link does not match crate name"}])
                        #     continue
                        dependent_info = parsing_git_commits.get_info_about_dependency(dependents[dependent]['github_url'], dependent, package_name, patched_version)
                        print([id, package_name, dependent, dependent_info])
                        csv_writer.writerow([id, package_name, dependent, dependent_info])

#process_rustsec_jsons() 
get_dependent_patch_info()


        
        
