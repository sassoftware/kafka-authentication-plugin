#!/bin/bash
#
# This script is used to invoke a command-line utility which prompts
# the user for credentials (username + password) and produces the
# encoded string that should be stored in a property file to authenticate
# that user later.
#


# Get the name of the jar file produced by the build
jarfile=$(ls -1 build/libs/kafka-authentication-plugin-*.jar)
fileResult=$?
if [ $fileResult -ne 0 ]; then
    ./gradlew build
    buildResult=$?
else
    buildResult=0
fi


if [ $buildResult -eq 0 ]; then
    java -cp build/libs/kafka-authentication-plugin-*.jar com.sas.kafka.auth.AuthenticationCredentialCmdLine
else
    echo ""
    echo "Failed to build kafka authentication jar using Gradle"
fi
echo ""
