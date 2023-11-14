from typing import Union
import os
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from cvss import CVSS2, CVSS3 # converts CVSS strings to score


def json_to_row(file_path: str):
    """Given a file path to a json file in the OSV format, returns a populated dataframe."""
    with open(file_path, 'r') as file:
        data = json.load(file)
    if "withdrawn" in data:
        return None
    
    #filter out for not crates.io
    if not data["affected"] or not data["affected"]["package"] or not data["affected"]["package"]["ecosystem"] or data["affected"]["package"]["ecosystem"] != "crates.io":
        return
    
    row = []
    row.append(data["id"])
    row.append(data["affected"]["package"]["name"])


    found_github = False
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
    if found_github == False:
        row.append("")
        row.append("")
    
    row.append(data["affected"]["package"]["purl"])

    if data["affected"]["ranges"] and data["affected"]["ranges"]["events"] and data["affected"]["ranges"]["events"]["introduced"]:
        row.append(data["affected"]["ranges"]["events"]["introduced"])
    else:
        row.append("")

    if data["affected"]["ranges"] and data["affected"]["ranges"]["events"] and data["affected"]["ranges"]["events"]["fixed"]:
        row.append(data["affected"]["ranges"]["events"]["fixed"])
    else:
        row.append("")

    #get dependents' via github. all dependents, including historical ones


    
    

# Folder containing RustSec advisories in the OSV format
folder_path = './advisory-db-osv/crates/'



# Read in all vulnerabilities
first_row = ["id", "name", "owner", "repo", "purl", "introduced_version", "patched_version", "dependents"]
all_rows = []
for filename in os.listdir(folder_path):
    if filename.endswith('.json'):
        # Construct the full path to the JSON file
        file_path = os.path.join(folder_path, filename)
        # Read the JSON file into a DataFrame
        osv = json_to_row(file_path)
        if osv is not None:
            all_rows.append(osv)
