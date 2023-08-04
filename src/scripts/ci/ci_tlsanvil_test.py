# Script to run inside the CI container to test the botan
# TLS client/server with TLS-Anvil
#
# (C) 2023 Jack Lloyd
# (C) 2023 Fabian Albert, Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)
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
    Create a X.509 certificate and associated RSA key at Config.key_and_cert_storage_path
    using Botan's CLI.

    Returns: (<cert path>, <key path>)
    """

    key_path = os.path.join(Config.key_and_cert_storage_path, Config.tmp_key_file_name)
    cert_path = os.path.join(Config.key_and_cert_storage_path, Config.tmp_cert_file_name)

    with open(key_path, 'w', encoding='utf-8') as keyfile:
        subprocess.run([botan_exe_path, "keygen", "--algo=RSA", "--params=2048"], stdout=keyfile, check=True)

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
        "-connectionTimeout", "5000",
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
    parser.add_argument("--botan-exe", help="Botan executable file", required=True)
    parser.add_argument("--tlsanvil-jar", help="TLS-Anvil test suite jar file", required=True)
    parser.add_argument("--test-target", help="The TLS side to test", choices=['client', 'server'], required=True)

    args = vars(parser.parse_args(args))

    if not os.path.isfile(args["tlsanvil_jar"]):
        raise FileNotFoundError(f"Unable to find '{args['tlsanvil_jar']}'")

    if not os.path.isfile(args["botan_exe"]):
        raise FileNotFoundError(f"Unable to find '{args['botan_exe']}'")

    if args["test_target"] == "server":
        server_test(args["botan_exe"], args["tlsanvil_jar"])
    elif args["test_target"] == "client":
        client_test(args["botan_exe"], args["tlsanvil_jar"])

    return 0

if __name__ == "__main__":
    sys.exit(main())
