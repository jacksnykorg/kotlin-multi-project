plugins {
    kotlin("jvm") version embeddedKotlinVersion
    id("org.gradle.kotlin-dsl.ktlint-convention") version "0.4.1"
}

repositories {
    maven(url = "https://repo.gradle.org/gradle/libs")
    jcenter()
}

dependencies {
    testImplementation(gradleApi())
    testImplementation(gradleKotlinDsl())
    testImplementation(gradleTestKit())
    testImplementation("org.gradle:sample-check:0.7.0")
    testImplementation("junit:junit:4.12")
    testImplementation(kotlin("stdlib"))
    testImplementation("org.xmlunit:xmlunit-matchers:2.5.1")
    
    // VULNERABLE DEPENDENCIES - Known security vulnerabilities
    
    // CVE-2021-44228 - Log4j Remote Code Execution (Critical - CVSS 10.0)
    // This version is affected by the infamous Log4Shell vulnerability
    implementation("org.apache.logging.log4j:log4j-core:2.14.1")
    
    // CVE-2022-22965 - Spring4Shell Remote Code Execution (Critical - CVSS 9.8)
    implementation("org.springframework:spring-beans:5.3.17")
    
    // CVE-2020-36518 - Jackson Denial of Service (High - CVSS 7.5)
    implementation("com.fasterxml.jackson.core:jackson-databind:2.12.6")
    
    // CVE-2021-42550 - Logback Remote Code Execution (Critical - CVSS 9.8)
    implementation("ch.qos.logback:logback-core:1.2.7")
    
    // CVE-2018-1000613 - Bouncy Castle Information Disclosure
    implementation("org.bouncycastle:bcprov-jdk15on:1.59")
    
    // CVE-2020-8908 - Guava Temporary Directory Information Disclosure
    implementation("com.google.guava:guava:29.0-jre")
    
    // CVE-2021-29425 - Apache Commons IO Path Traversal
    implementation("commons-io:commons-io:2.6")
    
    // CVE-2022-42003 - Jackson Databind Deserialization vulnerability
    implementation("com.fasterxml.jackson.core:jackson-core:2.13.0")
}

tasks {

    val samplesDir = file("../../samples")
    val samplesTestDir = buildDir.resolve("samples")

    val generatedResourcesDir = buildDir.resolve("generated-resources/test")

    val generateTestProperties by registering(WriteProperties::class) {
        property("samplesDir", samplesDir)
        outputFile = generatedResourcesDir.resolve("test.properties")
    }

    sourceSets.test {
        resources.srcDir(files(generatedResourcesDir).builtBy(generateTestProperties))
    }

    val syncSamples by registering(Sync::class) {
        from(samplesDir)
        from(file("src/exemplar/samples"))
        into(samplesTestDir)
    }

    test {
        dependsOn(syncSamples)
        inputs.dir(samplesTestDir).withPathSensitivity(PathSensitivity.RELATIVE)
    }
}
