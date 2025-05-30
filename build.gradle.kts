plugins {
    id("java")
}

group = "com.parameter.collector"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.4")
    implementation("com.google.code.gson:gson:2.10.1")
}

tasks.withType<JavaCompile> {
    sourceCompatibility = "21"
    targetCompatibility = "21"
    options.encoding = "UTF-8"
}

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })
    manifest {
        attributes(
            "Main-Class" to "com.parameter.collector.ParameterCollector",
            "Extension-Name" to "Parameter Collector",
            "Extension-Description" to "Automatically collects and displays HTTP parameters from Burp Suite",
            "Extension-Author" to "Your Name"
        )
    }
    archiveBaseName.set("parameter-collector")
}