import csv
from glob import glob


res_files = glob("*-bench.csv")
with open("agg-results.csv", 'w', newline='') as a:
    agg = csv.writer(a)
    agg.writerow(['name', 'circuit', 'runtime'])
    for res in res_files:
        with open(res, 'r', newline='') as rfl:
            r = csv.DictReader(rfl)
            for b in r:
                agg.writerow([res.split('/')[-1].split('-')[0], b['case'], b['runtime']])
