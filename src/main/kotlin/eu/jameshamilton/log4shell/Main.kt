package eu.jameshamilton.log4shell

import proguard.classfile.AccessConstants.PRIVATE
import proguard.classfile.ClassPool
import proguard.classfile.visitor.AllMemberVisitor
import proguard.classfile.visitor.ClassCounter
import proguard.classfile.visitor.ConstructorMethodFilter
import proguard.classfile.visitor.MemberAccessFilter
import proguard.classfile.visitor.MemberCounter
import proguard.classfile.visitor.MemberDescriptorFilter
import proguard.classfile.visitor.MethodFilter
import proguard.io.DexClassReader
import proguard.io.NameFilteredDataEntryReader
import proguard.io.util.IOUtil.read
import java.io.File

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("Usage: log4shell-detector <jar-file>")
        return
    }

    val vulnerableFiles = when (val input = File(args.first())) {
        input -> input.walk()
            .filter { it.isFile && it.extension in listOf("jar", "war", "dex", "apk", "aar", "class", "zip") }
            .map { if (check(it)) it else null }.filterNotNull().toList()
        else -> if (check(input)) listOf(input) else emptyList()
    }

    if (vulnerableFiles.isEmpty()) {
        println("No log4shell found")
    } else {
        println(
            """
        |WARNING: log4j < 2.15.0 vulnerable to CVE-2021-44228 found in:
        |
        |${vulnerableFiles.joinToString(separator = "") { "\t- ${it.name}\n" }}
        |For more information see: https://logging.apache.org/log4j/2.x/security.html
        """.trimMargin()
        )
    }
}

fun check(file: File): Boolean = check(readInput(file))
fun check(programClassPool: ClassPool): Boolean {
    val jndiLookupCounter = ClassCounter()

    // A workaround for CVE-2021-44228 is to remove the `JndiLookup` class,
    // so check that exists first. https://www.kb.cert.org/vuls/id/930724#workarounds
    //
    // Prefix with `**` to take into account shadow packing.
    programClassPool.classesAccept("**org/apache/logging/log4j/core/lookup/JndiLookup", jndiLookupCounter)

    if (jndiLookupCounter.count == 0) return false

    val jndiManagerOldConstructorCounter = MemberCounter()

    // Versions prior to 2.15.0 have the following constructor in JndiManager:
    // private <init>(Ljava/lang/String;Ljavax/naming/Context;)V
    //
    // https://github.com/apache/logging-log4j2/blob/rel/2.14.1/log4j-core/src/main/java/org/apache/logging/log4j/core/net/JndiManager.java
    //
    // Based on Yara rule https://github.com/darkarnium/Log4j-CVE-Detect/blob/main/rules/vulnerability/log4j/CVE-2021-44228.yar

    programClassPool.classesAccept(
        // Prefix with `**` to take into account shadow packing.
        "**org/apache/logging/log4j/core/net/JndiManager",
        AllMemberVisitor(
            MethodFilter(
                ConstructorMethodFilter(
                    MemberAccessFilter(
                        /* requiredSetAccessFlags = */ PRIVATE, /* requiredUnsetAccessFlags = */ 0,
                        MemberDescriptorFilter(
                            "(Ljava/lang/String;Ljavax/naming/Context;)V",
                            jndiManagerOldConstructorCounter
                        )
                    )
                )
            )
        )
    )

    return jndiManagerOldConstructorCounter.count > 0
}

private fun readInput(inputFile: File): ClassPool =
    read(inputFile.absolutePath, "**", true) { dataEntryReader, classPoolFiller ->
        NameFilteredDataEntryReader(
            "classes*.dex",
            DexClassReader(
                false,
                classPoolFiller
            ),
            dataEntryReader
        )
    }
