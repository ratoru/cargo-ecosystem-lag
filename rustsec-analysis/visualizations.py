import pandas as pd
import matplotlib.pyplot as plt
import json
from cvss import CVSS2, CVSS3

url = 'https://raw.githubusercontent.com/ratoru/cargo-ecosystem-lag/rustsec/rustsec-analysis/all_vulns_info3.cvs'
df = pd.read_csv(url, index_col = 0, on_bad_lines = 'skip')

#time to resolve for packages = date of patch - date of publication
print(df.head(5))
print(df.describe())

#we have 519 vulnerabilities for which data is comprehensive enough
print(df.loc[:, 'severity'])
print(df.loc[:, 'categories_vuln'])

selected_columns = ['severity', 'categories_vuln']
new_df = df[selected_columns]

new_severity_dict = []
for string_data in df.loc[:, 'severity']:
    parsed_data = json.loads(string_data.replace("'", '"'))
    new_severity_dict.append(parsed_data)

severity_score = []
test = new_severity_dict[4]
string = test[0]

for index in new_severity_dict:
    dict = index[0]
    if len(dict) != 0:
        c = CVSS3(dict['score'])
        c.clean_vector()
        severity_score.append(c.scores())

print(severity_score)
