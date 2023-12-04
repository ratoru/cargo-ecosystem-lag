import pandas as pd
import matplotlib.pyplot as plt
import json
from cvss import CVSS2, CVSS3
import numpy as np
import seaborn as sb

url = 'https://raw.githubusercontent.com/ratoru/cargo-ecosystem-lag/rustsec/rustsec-analysis/all_vulns_info3.cvs'
df = pd.read_csv(url, index_col = 0, on_bad_lines = 'skip')

#time to resolve for packages = date of patch - date of publication
print(df.head(5))
print(df.describe())

#we have 519 vulnerabilities for which data is comprehensive enough
print(df.loc[:, 'severity'])
print(df.loc[:, 'categories_vuln'])



severity_score = []

for string_data in df.loc[:, 'severity']:
    if len(string_data) > 10:
        end = len(string_data) - 3
        print(string_data[31:end])
        c = CVSS3(string_data[31:end])
        c.clean_vector()
        severity_score.append(sum(c.scores()))
    else: 
        severity_score.append(0)

print(severity_score)
data = severity_score #Generating data.
plt.figure(figsize = (5,5))
sb.kdeplot(data , bw = 0.5 , fill = True).set(title='Density Plot of Severity Score', xlabel='Severity Scores', ylabel='Density')
plt.show()


selected_columns = ['categories_vuln']
df.insert(2, "numeric_severity", severity_score, True)

df_expanded = df.explode('categories_vulns')

# Create a boxplot using seaborn
plt.figure(figsize=(10, 6))
sns.boxplot(x='categories_vulns', y='numeric_severity', data=df_expanded)
plt.title('Boxplot of Numeric Severity by Categories Vulns')
plt.xlabel('Categories Vulns')
plt.ylabel('Numeric Severity')
plt.show()

