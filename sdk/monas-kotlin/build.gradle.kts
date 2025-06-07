plugins {
    kotlin("jvm") version "2.1.20"
}

group = "com.github.monas"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    implementation("io.github.charlietap.chasm:chasm:0.9.70")
}

val cargoBuild by tasks.registering(Exec::class) {
    group = "build"
    description = "Builds the Rust project using cargo"
    workingDir = file("${projectDir}/../../wasm-module-proto")
    commandLine = listOf("bash", "-c", "cargo build --release --target wasm32-wasip1")
}

val copyWasmModule by tasks.registering(Copy::class) {
    group = "build"
    description = "Copies the built Rust WASM module to the resources directory"
    from(file("${projectDir}/../../target/wasm32-wasip1/release")) {
        include("*.wasm")
    }
    into(file("${projectDir}/src/main/resources/wasm"))
    dependsOn(cargoBuild)
}

tasks.named("processResources") {
    dependsOn(copyWasmModule)
}

tasks.test {
    useJUnitPlatform()
}
// Kotlin のコンパイル前に cargoBuild を実行
kotlin {
    jvmToolchain(21)
}