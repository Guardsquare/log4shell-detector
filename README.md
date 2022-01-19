# Log4Shell detector

Yet another log4shell detector, similar to [log4jscanner](https://github.com/google/log4jscanner),
[log4j-detector](https://github.com/mergebase/log4j-detector) etc but built with [ProGuardCORE](https://github.com/Guardsquare/proguard-core).

It detects the usage of log4j versions vulnerable to CVE-2021-44228. 

For more information about the vulnerability see [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8984) 
and [Apache Log4j Security Vulnerabilities](https://logging.apache.org/log4j/2.x/security.html).

# Executing

You can download the [release distribution](https://github.com/Guardsquare/log4shell-detector/releases/tag/v1.0.0), extract and run the shell/bat script. The input can be a jar file, class file, directory, Android aar or Android apk.

```
$ bin/log4shell-detector <path-to-jar>
```

Or you can clone this repository and execute via Gradle:

```bash
$ ./gradlew run --args=/path/to/my.jar
```

# Building

The application can be built from source via Gradle:

```
$ ./gradlew build
```

This will generate distribution archives in the `build/distributions` directory.

# How does it work?

The detector looks for a specific constructor that appears in log4j < 2.15.0,
similar to [this Yara rule](https://github.com/darkarnium/Log4j-CVE-Detect/blob/main/rules/vulnerability/log4j/CVE-2021-44228.yar).

[ProGuardCORE](https://github.com/Guardsquare/proguard-core) is used to parse the input, and a combination of class and member
filters are used to look for the specific constructor.

[dex2jar](https://github.com/pxb1988/dex2jar) is used to convert dex files in Android APKs files to class files.

# Shadow packed log4j

Shadow packed versions of log4j should be detected, for example if
the log4j package is renamed to `com/example/org/apache/logging/log4j`.

# Obfuscated applications

If an application is obfuscated then the detector may not detect the vulnerability,
since it is name based.
