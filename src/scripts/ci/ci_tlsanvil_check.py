"""
  Parses a TLS-Anvil results directory. Returns 0 iff all results are expected.
  Usage: ci_tlsanvil_check.py <path to results directory> [--verbose]
"""
import sys
import argparse
import os
import json
import logging

failure_level = {
    "STRICTLY_SUCCEEDED": 0,
    "DISABLED": 1,
    "CONCEPTUALLY_SUCCEEDED": 2,
    "PARTIALLY_FAILED": 3,
    "FULLY_FAILED": 4,
}

def expected_result_for(method_id: str):
    """ Get the expected result for a given test id """
    allowed_to_conceptually_succeed = {
        #    "client.tls12.rfc5246.TLSRecordProtocol.sendNotDefinedRecordTypesWithCCSAndFinished"
    }

    allowed_to_partially_fail = {}

    allowed_to_fully_fail = {}

    if method_id in allowed_to_fully_fail:
        return failure_level["FULLY_FAILED"]

    if method_id in allowed_to_partially_fail:
        return failure_level["PARTIALLY_FAILED"]

    if method_id in allowed_to_conceptually_succeed:
        return failure_level["CONCEPTUALLY_SUCCEEDED"]

    return failure_level["STRICTLY_SUCCEEDED"]


def test_result_valid(method_id: str, result: str):
    """
    Checks if a results for a given method name is valid.

    Return True iff the result is valid for the method.
    """

    if result == "DISABLED":
        return True

    return failure_level[result] <= expected_result_for(method_id)


def failing_test_info(json_data, method_id) -> str:
    info_str = ""
    try:
        method_class, method_name = method_id.rsplit('.', 1)
        info = [f"Error: {method_id} - Unexpected result '{json_data['Result']}'"]
        info += [""]
        info += [f"Class Name: 'de.rub.nds.tlstest.suite.tests.{method_class}'"]
        info += [f"Method Name: '{method_name}'"]
        info += [""]
        if json_data['TestMethod']['RFC'] is not None:
            info += [ f"RFC {json_data['TestMethod']['RFC']['number']}, Section {json_data['TestMethod']['RFC']['Section']}:"]
        else:
            info += ["Custom Test Case:"]
        info += [f"{json_data['TestMethod']['Description']}"]
        info += [""]

        info += [f"Result: {json_data['Result']} (expected {list(failure_level.keys())[list(failure_level.values()).index(expected_result_for(method_id))]})"]
        if json_data['DisabledReason'] is not None:
            info += [f"Disabled Reason: {json_data['DisabledReason']}"]


        additional_res_info = list({state["AdditionalResultInformation"] for state in json_data['States'] if state["AdditionalResultInformation"] != ""})
        additional_test_info = list({state["AdditionalTestInformation"] for state in json_data['States'] if state["AdditionalTestInformation"] != ""})
        state_result = [{state["Result"] for state in json_data['States']}]

        if len(state_result) > 1 or len(additional_res_info) > 1 or len(additional_test_info) > 1:
            info += ["Different results for different states. See test results artifact for more information."]

        if len(additional_res_info) == 1:
            info += ["", f"Additional Result Info: {additional_res_info[0]}"]

        if len(additional_test_info) == 1:
            info += ["", f"Additional Test Info: {additional_test_info[0]}"]
        info += [""]

        info_str = "\n".join(info)

        # Color in red
        info_str = "\n".join([f"\033[0;31m{line}\033[0m" for line in info_str.split("\n")])

        # In GitHub Actions logging group
        info_str = f"::group::{info_str}\n::endgroup::"




    except KeyError:
        logging.warning("Cannot process test info.")
        info_str = ""

    return info_str


def process_results_container(results_container_path: str):
    """
    Given a path, process the respective results container .json file.
    Returns True, iff the results of the container are expected.
    """
    success = False
    with open(results_container_path, "r", encoding="utf-8") as results_container_file:
        try:
            json_data = json.load(results_container_file)
            method_id = ".".join(
                [
                    json_data["TestMethod"]["ClassName"],
                    json_data["TestMethod"]["MethodName"],
                ]
            ).removeprefix("de.rub.nds.tlstest.suite.tests.")
            result = json_data["Result"]
            is_valid = test_result_valid(method_id, result)
            if is_valid:
                logging.debug("%s: '%s' -> ok", method_id, result)
                success = True
            else:
                # Print a GitHub logging group in red
                logging.error(failing_test_info(json_data, method_id))

        except KeyError:
            logging.error("Json file '%s' has missing entries.", results_container_path)

    return success


def main(args=None):
    """Parse args and check all result container files"""
    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true", default=False)
    parser.add_argument("results-dir", help="directory of TLS-Anvil test results")

    args = vars(parser.parse_args(args))

    logging.basicConfig(
        level=(logging.DEBUG if args["verbose"] else logging.INFO),
        format="%(message)s",
    )

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

    logging.info(
        "(%i/%i) test methods successful.",
        total_methods_count - failed_methods_count,
        total_methods_count,
    )
    total_success = failed_methods_count == 0
    logging.info("Total result: %s", "Success." if total_success else "Failed.")

    return int(not total_success)


if __name__ == "__main__":
    sys.exit(main())
