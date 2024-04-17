# Kafka Authentication Plugin

This repository contains the Java source code implementation of an Apache Kafka plugin
that performs client authentication against an external source such an an LDAP server.
When configured to use this plugin, the Kafka broker will perform user authentication
against the external source using the username and password provided by the Kafka client.

## Prerequisites

* Java JDK 15 or higher

## Getting Started

The Kafka Authentication plugin build produces a Java jar file which must be added to
the Kafka broker classpath.  To produce the jar file using a local build command:

```
./gradlew clean build jar -x test
```

The result is the `build/libs/kafka-authentication-plugin-<version>.jar` which contains
all the class files which implement the SASL callback handler.  This jar file
must be added to the classpath of the Kafka broker prior to starting the server.
You can do this by either copying the jar file into the `$KAFKA_HOME/libs`
directory or by setting the classpath environment variable:

```
export CLASSPATH="/path/to/jar/kafka-authentication-plugin-<version>.jar"
```

## Contributing

We welcome your contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to submit contributions to this project.

## License

This project is licensed under the [Apache 2.0 License](LICENSE).

## Additional Resources

* [KIP-86](https://cwiki.apache.org/confluence/pages/viewpage.action?pageId=65874679): Configurable SASL callback handlers
* Confluent [Apache Kafka Security](https://developer.confluent.io/courses/security/authorization/) course

## Alternatives

There are several open source alternatives to this library:

* [ultratendency/kafka-ldap-integration](https://github.com/ultratendency/kafka-ldap-integration/)
* [apache/rancher](https://github.com/apache/ranger/tree/master/plugin-kafka)
