"""
Run all tests in a file called "tests.json" (should be located in the current directory
"""

from pathlib import Path
from os import path
import sys
import json

base_dir = Path(__file__).parent.resolve()
common_services_dir = (base_dir / '../src').resolve()
sys.path.insert(0, str(common_services_dir))

from baseline_verify import netpol_verify_main


def run_netpol_gen(test_record):
    """
    Runs netpol_gen with args taken from the given test
    :param dict test_record: the test record
    :return bool: True if calling netpol_gen_main() was successful,  False otherwise
    """
    args = ['-r', test_record['repo']]
    for baseline in test_record.get('baselineFiles', []):
        args += ['-b', path.join('../baseline-rules/examples', baseline)]
    args += [path.join('netpols', test_record['netpols'])]

    args_str = ' '.join(args)
    print(f'Running baseline_verify with args: {args_str}')
    # noinspection PyBroadException
    try:
        ret_val = netpol_verify_main(args)
        expected_ret_val = test_record['expected']
        if ret_val != expected_ret_val:
            print(f'Unexpected return value. Expected {expected_ret_val}, got {ret_val}')
            return False
        return True
    except BaseException as ex:
        print('Error: Executing netpol_gen failed: ' + str(ex))
        return False


def run_test(test_record):
    """
    Runs a single test with given args, and compares its results with golden results
    :param dict test_record: The test details
    :return bool: True if test passed, False otherwise
    """
    if not run_netpol_gen(test_record):
        print('Test failed\n')
        return False

    print('Test passed\n')
    return True


if __name__ == '__main__':
    with open('tests.json') as tests_file:
        tests = json.load(tests_file)
        failed_tests = []
        for test_num, test in enumerate(tests, 1):
            test_name = test.get('name')
            print(f'Running test {test_num}: {test_name}')
            if not run_test(test):
                failed_tests.append(test_num)

    if failed_tests:
        print(f'{len(failed_tests)}/{test_num} tests failed: {failed_tests}')
    else:
        print(f'All {test_num} tests passed')
    sys.exit(len(failed_tests) > 0)
