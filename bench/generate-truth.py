from util import get_valid_ciruits, run_circuit, bcolors
import csv

circuits = get_valid_ciruits('..')

with open('test-cases.csv', 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['case', 'output'])
    for c in circuits:
        print(f"{bcolors.OKGREEN}Running Circuit{bcolors.ENDC}: {bcolors.OKBLUE}{c}{bcolors.ENDC}")
        res = run_circuit(c, '..', 'baseline')
        w.writerow([c, res.output])
