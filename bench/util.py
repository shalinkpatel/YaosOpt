from glob import glob
from typing import List, Dict
from dataclasses import dataclass
from subprocess import run, Popen
import time
import csv


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


@dataclass
class CircuitResult:
    output: str
    time: float


def get_valid_ciruits(folder: str) -> List[str]:
    cs = filter(lambda s: '-' not in s, glob(f"{folder}/circuits/*.txt"))
    return list(map(lambda c: c.split('/')[-1].split('.')[0], cs))


def run_circuit(cname: str, folder: str, vers: str) -> CircuitResult:
    garbler = Popen(f"{folder}/archive/yaos_garbler_{vers} {folder}/circuits/{cname}.txt {folder}/circuits/{cname}-input-1.txt localhost 8000", shell=True)
    time.sleep(0.1)
    t = time.time()
    evaluator = run(f"{folder}/archive/yaos_evaluator_{vers} {folder}/circuits/{cname}.txt {folder}/circuits/{cname}-input-2.txt localhost 8000", capture_output=True, text=True, shell=True)
    t = time.time() - t
    garbler.poll()
    return CircuitResult(evaluator.stdout.strip(), t)


def get_test_cases(folder: str) -> Dict[str, str]:
    cases = {}
    with open(f"{folder}/bench/test-cases.csv", 'r', newline='') as f:
        r = csv.DictReader(f)
        for row in r:
            cases[row['case']] = row['output']
    return cases
