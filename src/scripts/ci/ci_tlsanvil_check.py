"""
  Parses a TLS-Anvil results directory. Returns 0 iff all results are expected.
  Usage: ci_tlsanvil_check.py <path to results directory> [--verbose]
"""
import sys
import argparse
import os
import json
import logging

def test_result_valid(method_name: str, result: str):
    """
    Checks if a results for a given method name is valid. It contains lists
    of test methods that are allowed to only partially succeed or even fail.

    Return True iff the result is valid for the method.
    """
    allowed_to_conceptually_succeed = {

    }

    allowed_to_partially_fail = {

    }

    allowed_to_fully_fail = {

    }

    failure_level = {"STRICTLY_SUCCEEDED": 0, "DISABLED": 1, "CONCEPTUALLY_SUCCEEDED": 2,
                    "PARTIALLY_FAILED": 3, "FULLY_FAILED": 4 }

    is_valid = False

    if result not in failure_level:
        logging.error("Unknown result key: %s. Skipped...", result)
        is_valid = True

    if failure_level[result] == failure_level["STRICTLY_SUCCEEDED"]:
        is_valid = True
    elif failure_level[result] <= failure_level["DISABLED"]:
        is_valid = True
    elif (failure_level[result] <= failure_level["CONCEPTUALLY_SUCCEEDED"]
          and method_name in allowed_to_conceptually_succeed):
        is_valid = True
    elif (failure_level[result] <= failure_level["PARTIALLY_FAILED"]
          and method_name in allowed_to_partially_fail):
        is_valid = True
    elif method_name in allowed_to_fully_fail:
        is_valid = True

    return is_valid

def process_results_container(results_container_path: str):
    """
    Given a path process the respective results container .json file.
    Returns True, iff the results of the container are expected.
    """
    success = False
    with open(results_container_path, "r", encoding="utf-8") as results_container_file:
        try:
            json_data = json.load(results_container_file)
            method_name = json_data["TestMethod"]["MethodName"]
            result = json_data["Result"]
            is_valid = test_result_valid(method_name, result)
            if is_valid:
                logging.debug("%s: '%s' -> ok", method_name, result)
                success = True
            else:
                logging.error("%s: Unexpected result '%s'.", method_name, result)

        except KeyError:
            logging.error("Json file '%s' has missing entries.", results_container_path)

    return success



def main(args=None):
    """ Parse args and check all result container files """
    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true", default=False)
    parser.add_argument("results-dir", help="directory of TLS-Anvil test results")

    args = vars(parser.parse_args(args))

    logging.basicConfig(level=(logging.DEBUG if args['verbose'] else logging.INFO),
                        format='[%(levelname)s] %(message)s')

    results_dir = args["results-dir"]

    if not os.access(results_dir, os.X_OK):
        raise FileNotFoundError("Unable to read TLS-Anvil results dir")

    failed_methods_count = 0
    total_methods_count = 0
    for root, _, files in os.walk(results_dir):
        for file in files:
            if file == "_containerResult.json":
                abs_path = os.path.abspath(os.path.join(root, file))
                total_methods_count += 1
                if not process_results_container(abs_path):
                    failed_methods_count += 1

    logging.info("(%i/%i) test methods successful.",
                 total_methods_count - failed_methods_count,
                 total_methods_count)
    total_success = failed_methods_count == 0
    logging.info("Total result: %s", "Success." if total_success else "Failed.")

    return int(not total_success)


if __name__ == "__main__":
    sys.exit(main())
