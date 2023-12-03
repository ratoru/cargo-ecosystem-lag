import requests
from datetime import datetime
from urllib.parse import urlparse

access_token = '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'

#Set up headers with the access token
headers = {
    'Authorization': f'token {access_token}',
    'Accept': 'application/vnd.github.v3+json'
}

def compare_cargo_versions(A, B):
    """
        A (str): The first version number as a string.
        B (str): The second version number as a string.
    Returns:
        int: -1 if version A comes before version B, 0 if they're equal, and 1 if version A comes after version B.
    """
    version_A = list(map(int, A.split('.')))
    version_B = list(map(int, B.split('.')))

    # Make sure both version lists have the same number of components
    while len(version_A) < len(version_B):
        version_A.append(0)
    while len(version_B) < len(version_A):
        version_B.append(0)

    # Compare each component of the version
    for a, b in zip(version_A, version_B):
        if a < b:
            return -1
        elif a > b:
            return 1
    return 0

#returns -1 if date1 came before date2, 0 if theyre the same, 1 if date1 came after date2
def compare_date_strings(date_str1, date_str2):
    format_str = '%Y-%m-%dT%H:%M:%SZ'
    
    # Convert date strings to datetime objects
    date1 = datetime.strptime(date_str1, format_str)
    date2 = datetime.strptime(date_str2, format_str)

    # Perform the comparison
    if date1 < date2:
        return -1
    elif date1 == date2:
        return 0
    else:
        return 1

def get_all_commits(github_link):
    parsed_url = urlparse(github_link)
    repo = parsed_url.path.split("/")[-1]
    owner = parsed_url.path.split("/")[-2]
    # Define the API endpoint
    url = f'https://api.github.com/repos/{owner}/{repo}/commits'

    # Make the GET request
    response = requests.get(url, headers=headers)

    # Check the status code
    if response.status_code == 200:
        # Successful request
        commits = response.json()
        return commits
    else:
        # Error handling
        print(url)
        print(f"Error: {response.status_code}")
        print(response.text)
        return None
    
def get_commit_details(commit_url):
    # Set up headers with the access token

    # Make the GET request to the commit URL
    response = requests.get(commit_url, headers=headers)

    # Check the status code
    if response.status_code == 200:
        # Successful request
        commit_details = response.json()
        return commit_details
    else:
        # Error handling
        print(f"Error: {response.status_code}")
        print(response.text)
        return None

# Replace these with your own values
owner = 'jaredforth' #'libwebp-sys'
repo = 'webp' #NoXF
vulnerable_dependency = 'libwebp-sys'
patched_version = '0.9.3'

def get_dependency_version(file_info, s):
    try:
        index_dependency = file_info['patch'].find(s)
        #print(file_info['patch'])
        substr = file_info['patch'][index_dependency+len(vulnerable_dependency)+4:]
        #print(substr)
        dependency_version = (substr[:substr.find('\n')]).strip('\"')
        #need to account for case where this info is structured as a json
        if 'version =' in dependency_version:
            i = dependency_version.find('version =')
            n = i + len('version =') + 2
            v = dependency_version[n:]
            i_ = v.find('\"')
            dependency_version = v[:i_]
        return dependency_version

    except:
        return None

def get_info_about_dependency(github_link, repo, vulnerable_dependency, patched_version):
    # Get all commits from the specified repository
    all_commits = get_all_commits(github_link)

    if not all_commits:
        return {"dependency_patched":True, "dependent_on_vuln_version": False, "error" : "could not get commits from github"}
    # Print commit information
    res = {"dependency_patched":True, "dependent_on_vuln_version": False, "found_patch":False}
    
    if all_commits:
        for commit in all_commits:
            # print(f"Commit SHA: {commit['sha']}")
            # print(f"Author: {commit['commit']['author']['name']}")
            # print('-' * 50)

            commit_details = get_commit_details(commit['url'])

            files_affected = commit_details['files']
            if files_affected:
                for file_info in files_affected:
                    if file_info['filename'] == 'Cargo.toml':
                        if 'patch' in file_info:
                            #print(file_info['patch'])
                            s_new = "+" + vulnerable_dependency + " " 
                            s_old = "-" + vulnerable_dependency + " " 
                            if s_new in file_info['patch']:
                                dependency_version_new = get_dependency_version(file_info, s_new)
                                dependency_version_old = get_dependency_version(file_info, s_old)

                                if dependency_version_old == None:
                                    print("could not get old dependency version")
                                if dependency_version_new == None:
                                    print("could not get new dependency version")
                                
                                if dependency_version_old == None or dependency_version_new == None:
                                    break
                                
                                #check that this commit switched dependency from unpatched to patched version  
                                if compare_cargo_versions(dependency_version_old, patched_version) < 0 and compare_cargo_versions(dependency_version_new, patched_version) >= 0:
                                    
                                    #print("found upgrade to patched version of dependency")
                                    res["found_patch"] = True
                                    print("found patch!")

                                    #if we've captured a commit already, continue if this date came after the one we have. otherwise, override old info.
                                    if "time_upgrade" in res and compare_date_strings(commit['commit']['author']['date'], res["time_upgrade"]) > -1:
                                        break

                                    res["time_upgrade"] = commit['commit']['author']['date']
                                    res["commit_msg"] = commit['commit']['message']
                                    res["dependency_version_new"] = dependency_version_new

                                    # print(f"Date: {commit['commit']['author']['date']}")
                                    # print(f"Message: {commit['commit']['message']}")
                                    k = "-" + vulnerable_dependency
                                    index_old_version_dependency = file_info['patch'].find(k) + len(k) + 4
                                    #print('old version of dependency: ')
                                    res["dependency_version_old"] = file_info['patch'][index_old_version_dependency:index_old_version_dependency+5]
                                    #print(file_info['patch'][index_old_version_dependency:index_old_version_dependency+5])
                                    
                                    p = repo + '\"\n-version'
                                    #the same commit diff may include the new version of the dependent
                                    if p in file_info['patch']:
                                        #print("dependent version changed to ")
                                        j = "+version = \""
                                        index_new_version = file_info['patch'].find(j) + len(j)
                                        res["new_version"] = file_info['patch'][index_new_version:index_new_version+5]
                                        #print(file_info['patch'][index_new_version:index_new_version+5])
    
    return res

#returns the date that the orginal vulnerable package was updated
def get_date_of_patch(owner, repo, patched_version):
    # Get all commits from the specified repository
    all_commits = get_all_commits(owner, repo)

    date = 'none'

    if all_commits:
        for commit in all_commits:
            # print(f"Commit SHA: {commit['sha']}")
            # print(f"Author: {commit['commit']['author']['name']}")
            # print('-' * 50)

            commit_details = get_commit_details(commit['url'])

            files_affected = commit_details['files']
            if files_affected:
                for file_info in files_affected:
                    if file_info['filename'] == 'Cargo.toml':
                        if 'patch' in file_info:
                            s_new = "+version = \"" + patched_version
                            if s_new in file_info['patch']:
                                date = commit['commit']['author']['date']
                            
    return date              

owner = 'NoXF' 
repo = 'libwebp-sys'
patched_version = '0.9.3'

print(get_date_of_patch(owner, repo, patched_version))


#get_info_about_dependency(owner, repo, vulnerable_dependency, patched_version)

#data to collect:
#Cargo.lock - see edits to it 
# https://stackoverflow.com/questions/40393117/getting-file-diff-with-github-api


#goal: CVE->dependents->github of dependent packages/projects->all commits->diff for each commit in cargo.lock file->find package number

#example:
#https://rustsec.org/advisories/RUSTSEC-2023-0061.html 
#https://crates.io/crates/libwebp-sys - vulnerable library
#https://crates.io/crates/webp - dependent
#github of dependent: https://github.com/jaredforth/webp 



#check for multiple branches -- actually just take first edit
#if a dependent appears not to be patched, it could be because it was using a version less than the "introduced" version