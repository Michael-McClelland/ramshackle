import os
import json
import matplotlib.pyplot as plt
f = open(os.getcwd() + '/results/results_json.json')
data = json.load(f)
expected_failures = 8
actual_failures = 0
expected_passes = 9
actual_passes = 0
for i in data['results']['passed_checks']:
  actual_passes = actual_passes + 1
for i in data['results']['failed_checks']:
  actual_failures = actual_failures + 1
f.close()


labels = 'expected_failures', 'actual_failures', 'expected_passes', 'actual_passes'
sizes = [expected_failures,actual_failures,expected_passes,actual_passes]

fig, ax = plt.subplots()
ax.pie(sizes, labels=labels, autopct='%1.1f%%')
if not os.path.exists(os.getcwd() + '/images'):
  os.makedirs('./images')
fig.savefig(os.getcwd() + "/images/checkov_piechart.png")
