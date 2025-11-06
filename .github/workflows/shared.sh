#!/usr/bin/env bash

declare -ax dfuzzer=("dfuzzer")
if [[ "$TYPE" == valgrind ]]; then
        dfuzzer=("valgrind" "--leak-check=full" "--show-leak-kinds=definite" "--errors-for-leak-kinds=definite" "--error-exitcode=42" "dfuzzer")
fi

stop_test_server() {
        if command -v systemctl >/dev/null && systemctl -q list-unit-files dfuzzer-test-server.service >/dev/null; then
                # The test server was started as a systemd service
                sudo systemctl stop dfuzzer-test-server
        else
                # The test server was started directly via a D-Bus' service unit
                if ! command -v pkill; then
                        echo >&2 "Missing pkill binary, can't continue"
                        exit 1
                fi

                if sudo pkill -0 -x dfuzzer-test-server; then
                        sudo pkill -TERM -x dfuzzer-test-server
                        timeout 10s bash -xec "while sudo pkill -0 -x dfuzzer-test-server; do sleep .5; done"
                fi
        fi
}
