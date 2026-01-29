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
    
    // ==================== CRITICAL SEVERITY ====================
    
    // CVE-2021-44228 - Log4j Remote Code Execution (Critical - CVSS 10.0)
    // Log4Shell - the most critical vulnerability in recent history
    implementation("org.apache.logging.log4j:log4j-core:2.14.1")
    
    // CVE-2022-22965 - Spring4Shell Remote Code Execution (Critical - CVSS 9.8)
    implementation("org.springframework:spring-beans:5.3.17")
    
    // CVE-2017-5638 - Apache Struts RCE (Critical - CVSS 10.0)
    // Equifax breach vulnerability
    implementation("org.apache.struts:struts2-core:2.3.31")
    
    // CVE-2019-17571 - Log4j 1.x Socket Server RCE (Critical - CVSS 9.8)
    implementation("log4j:log4j:1.2.17")
    
    // CVE-2016-1000027 - Spring Web RCE via HttpInvoker (Critical - CVSS 9.8)
    implementation("org.springframework:spring-web:4.3.0.RELEASE")
    
    // CVE-2022-22978 - Spring Security Authorization Bypass (Critical - CVSS 9.8)
    implementation("org.springframework.security:spring-security-web:5.6.0")
    
    // CVE-2021-42550 - Logback Remote Code Execution (Critical - CVSS 9.8)
    implementation("ch.qos.logback:logback-core:1.2.7")
    
    // CVE-2018-1000613 - Bouncy Castle Deserialization RCE (Critical)
    implementation("org.bouncycastle:bcprov-jdk15on:1.59")
    
    // CVE-2015-7501 - Apache Commons Collections RCE (Critical - CVSS 9.8)
    implementation("commons-collections:commons-collections:3.2.1")
    
    // CVE-2020-9484 - Apache Tomcat Session Deserialization RCE (Critical)
    implementation("org.apache.tomcat:tomcat-catalina:9.0.30")
    
    // CVE-2019-0232 - Apache Tomcat CGI RCE (Critical)
    implementation("org.apache.tomcat.embed:tomcat-embed-core:8.5.0")
    
    // CVE-2022-23305 - Apache Log4j JDBCAppender SQL Injection (Critical)
    implementation("org.apache.logging.log4j:log4j-jdbc:2.14.1")
    
    // ==================== HIGH SEVERITY ====================
    
    // CVE-2020-36518 - Jackson Denial of Service (High - CVSS 7.5)
    implementation("com.fasterxml.jackson.core:jackson-databind:2.12.6")
    
    // CVE-2021-29425 - Apache Commons IO Path Traversal (High)
    implementation("commons-io:commons-io:2.6")
    
    // CVE-2022-42003 - Jackson Databind Deserialization vulnerability (High)
    implementation("com.fasterxml.jackson.core:jackson-core:2.13.0")
    
    // CVE-2018-11761 - Apache Tika XXE (High)
    implementation("org.apache.tika:tika-core:1.18")
    
    // CVE-2020-1945 - Apache Ant Insecure Temporary File (High)
    implementation("org.apache.ant:ant:1.9.4")
    
    // CVE-2021-22118 - Spring Framework Directory Traversal (High)
    implementation("org.springframework:spring-core:5.2.0.RELEASE")
    
    // CVE-2018-14720 - Jackson XML XXE (High)
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-xml:2.9.6")
    
    // CVE-2019-12086 - Jackson Databind Polymorphic Typing (High)
    implementation("com.fasterxml.jackson.core:jackson-annotations:2.9.0")
    
    // CVE-2022-25647 - Gson DoS (High)
    implementation("com.google.code.gson:gson:2.8.5")
    
    // CVE-2020-11979 - Apache Ant Zip Slip (High)
    implementation("org.apache.ant:ant-compress:1.5")
    
    // ==================== MEDIUM SEVERITY ====================
    
    // CVE-2020-8908 - Guava Temporary Directory Information Disclosure
    implementation("com.google.guava:guava:29.0-jre")
    
    // CVE-2018-10237 - Guava Unbounded Memory Allocation (Medium)
    implementation("com.google.guava:guava-jdk5:17.0")
    
    // CVE-2021-21295 - Netty HTTP Request Smuggling (Medium)
    implementation("io.netty:netty-codec-http:4.1.45.Final")
    
    // CVE-2020-7238 - Netty HTTP Request Smuggling (Medium)
    implementation("io.netty:netty-all:4.1.43.Final")
    
    // CVE-2018-8088 - SLF4J Binding Hijacking (Medium)
    implementation("org.slf4j:slf4j-ext:1.7.25")
    
    // CVE-2019-10086 - Apache Commons BeanUtils Property Injection (Medium)
    implementation("commons-beanutils:commons-beanutils:1.9.3")
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
