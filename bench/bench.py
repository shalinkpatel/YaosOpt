from util import get_valid_ciruits, run_circuit, bcolors
import csv
import sys


bench_name = sys.argv[1]
TRIES = 50
circuits = get_valid_ciruits('..')

with open(f'{bench_name}-bench.csv', 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['case', 'runtime'])
    for c in circuits:
        print(f"{bcolors.OKGREEN}Benchmarking Circuit{bcolors.ENDC}: {bcolors.OKBLUE}{c}{bcolors.ENDC} {bcolors.WARNING}", end='', flush=True)
        timings = []
        for _ in range(TRIES):
            res = run_circuit(c, '..')
            timings.append(res.time)
            print('.',  end='', flush=True)
        print(bcolors.ENDC, end='')
        print(f"{bcolors.FAIL} {sum(timings) / TRIES:.4f}s {bcolors.ENDC}")
        w.writerow([c, sum(timings) / TRIES])
