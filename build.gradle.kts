import java.security.MessageDigest

plugins {
    base
}

fun sha256(file: java.io.File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val bytes = file.readBytes()
    val hash = digest.digest(bytes)
    return hash.joinToString("") { "%02x".format(it) }
}

tasks {

    val samplesWrappers by registering {
        doLast {
            val wrapperFiles = wrapper.get().run {
                listOf(scriptFile, batchScript, jarFile, propertiesFile).associateBy { it.name }
            }
            val hashes = wrapperFiles.mapValues { sha256(it.value) }
            file("samples").walk().filter { it.isFile && it.name in wrapperFiles }.forEach { sampleWrapperFile ->
                wrapperFiles.getValue(sampleWrapperFile.name).let { wrapperFile ->
                    if (sha256(sampleWrapperFile) != hashes.getValue(sampleWrapperFile.name)) {
                        logger.lifecycle("Updating ${sampleWrapperFile.relativeTo(rootDir)}")
                        wrapperFile.copyTo(sampleWrapperFile, overwrite = true)
                    }
                }
            }
        }
    }

    wrapper {
        distributionType = Wrapper.DistributionType.ALL
        finalizedBy(samplesWrappers)
    }
}
