from util import get_test_cases, run_circuit, bcolors
import sys


vers = sys.argv[1]
cases = get_test_cases('..')
for c, t in cases.items():
    print(f"{bcolors.OKGREEN}Testing Circuit{bcolors.ENDC}: {bcolors.OKBLUE}{c}{bcolors.ENDC} ", end='', flush=True)
    res = run_circuit(c, '..', vers)
    passed = res.output == t
    status = f"{bcolors.OKCYAN}PASSED{bcolors.ENDC}" if passed else f"{bcolors.FAIL}FAILED{bcolors.ENDC}"
    print(status)
