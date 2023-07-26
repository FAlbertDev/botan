"""
Script to run inside the CI container to test the botan
TLS client/server with TLS-Anvil

Usage: CI
"""
import sys
import argparse
import os
import subprocess


class Config:
    """ Hardcoded configurations for this CI script """
    key_and_cert_storage_path = "/tmp/"
    test_suite_results_path = "./TestSuiteResults"
    tmp_key_file_name = "tmp_rsa_key.pem"
    tmp_cert_file_name = "tmp_rsa_cert.pem"
    server_dest_ip = "127.0.0.1"
    server_dest_port = 4433
    botan_server_log = "./logs/botan_server.log"


def create_cert_and_key(botan_exe_path):
    """
    Create a X.509 certificate and associated RSA key at base_path
    using Botan's CLI.

    Returns: (<cert path>, <key path>)
    """

    key_path = os.path.join(Config.key_and_cert_storage_path, Config.tmp_key_file_name)
    cert_path = os.path.join(Config.key_and_cert_storage_path, Config.tmp_cert_file_name)

    with open(key_path, 'w', encoding='utf-8') as keyfile:
        subprocess.run([botan_exe_path, "keygen", "--algo=RSA"], stdout=keyfile, check=True)

    with open(cert_path, 'w', encoding='utf-8') as certfile:
        subprocess.run([botan_exe_path, "gen_self_signed", key_path, "localhost"], stdout=certfile, check=True)

    return (cert_path, key_path)


def server_test(botan_exe_path: str, tls_anvil_jar_path: str):
    cert_path, key_path = create_cert_and_key(botan_exe_path)

    tls_anvil_cmd = [
        "java", "-jar", tls_anvil_jar_path,
        "-strength", "1",
        "-parallelHandshakes", "1",
        "-disableTcpDump",
        "-outputFolder", Config.test_suite_results_path,
        "-tags", "happyflow13", # tmp
        "server", "-connect", f"{Config.server_dest_ip}:{Config.server_dest_port}"
    ]

    botan_server_cmd = [
        botan_exe_path, "tls_server", cert_path, key_path, f"--port={Config.server_dest_port}"
    ]

    os.makedirs(os.path.dirname(Config.botan_server_log), exist_ok=True)

    # Run Botan and test is with TLS-Anvil
    with open(Config.botan_server_log, 'w', encoding='utf-8') as server_log_file:
        botan_server_process = subprocess.Popen(botan_server_cmd, stdout=server_log_file, stderr=server_log_file)
        subprocess.run(tls_anvil_cmd, check=True)
        botan_server_process.kill()


def client_test(botan_exe_path: str, tls_anvil_jar_path: str):
    raise NotImplementedError("Client tests not yet implemented")


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--server-test",
        action="store_true",
        default=False,
        help="Test the Botan TLS server",
    )
    parser.add_argument(
        "--client-test",
        action="store_true",
        default=False,
        help="Test the Botan TLS client",
    )
    parser.add_argument("botan-executable", help="botan executable file")
    parser.add_argument("tlsanvil-jar-file", help="TLS-Anvil test suite jar file")

    args = vars(parser.parse_args(args))

    if args["server_test"] == args["client_test"]:
        raise ValueError("Either 'server-test' or 'client-test' must be set")

    if not os.path.isfile(args["tlsanvil-jar-file"]):
        raise FileNotFoundError(f"Unable to find '{args['tlsanvil-jar-file']}'")

    if not os.path.isfile(args["botan-executable"]):
        raise FileNotFoundError(f"Unable to find '{args['botan-executable']}'")

    if args["server_test"]:
        server_test(args["botan-executable"], args["tlsanvil-jar-file"])
    else:
        client_test(args["botan-executable"], args["tlsanvil-jar-file"])


if __name__ == "__main__":
    sys.exit(main())
