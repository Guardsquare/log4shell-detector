import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.6.10"
    id("org.jlleitschuh.gradle.ktlint") version "10.1.0"
    application
}

group = "eu.jameshamilton"
version = "1.0"

repositories {
    mavenCentral()
    maven(url = "https://jitpack.io")
}

dependencies {
    implementation("com.github.Guardsquare:proguard-core:89f74ba111")
    testImplementation(kotlin("test"))
    testImplementation("io.kotest:kotest-runner-junit5-jvm:5.0.3")
    testImplementation("io.kotest:kotest-assertions-core-jvm:5.0.3")
    testImplementation("io.kotest:kotest-property-jvm:5.0.3")
    testImplementation("io.kotest:kotest-framework-datatest:5.0.3")
    testImplementation("io.mockk:mockk:1.12.2")
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}

application {
    mainClass.set("eu.jameshamilton.log4shell.MainKt")
}
