// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.cli.shell

import com.github.ajalt.clikt.testing.test
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlin.io.path.readText

class VexCommandTest :
    FunSpec({

        context("happy path") {

            test("writes a CycloneDX document to the user-specified path") {
                withTempFile(content = vulnlogYamlWithPurls()) { input ->
                    withTempDir(prefix = "vex-out") { outputDir ->
                        val target = outputDir.resolve("vex.cdx.json")

                        val result =
                            VexCommand().test(
                                "${input.absolutePath} --release 1.0.0 --format cyclonedx -o ${target.toAbsolutePath()}",
                            )

                        result.statusCode shouldBe 0
                        result.stderr shouldContain "Wrote: ${target.toAbsolutePath()}"
                        val content = target.readText()
                        content shouldContain "\"bomFormat\": \"CycloneDX\""
                        content shouldContain "\"specVersion\": \"1.7\""
                        content shouldContain "CVE-2026-1234"
                        content shouldContain "\"state\": \"not_affected\""
                        content shouldContain "\"ref\": \"pkg:generic/acme-web-app@1.0.0\""
                    }
                }
            }

            test("writes to stdout when -o is '-'") {
                withTempFile(content = vulnlogYamlWithPurls()) { input ->
                    val result = VexCommand().test("${input.absolutePath} --release 1.0.0 --format cyclonedx -o -")

                    result.statusCode shouldBe 0
                    result.stdout shouldContain "\"bomFormat\": \"CycloneDX\""
                }
            }

            test("a rerun without changes reports the output as unchanged") {
                withTempFile(content = vulnlogYamlWithPurls()) { input ->
                    withTempDir(prefix = "vex-out") { outputDir ->
                        val target = outputDir.resolve("vex.cdx.json")
                        val arguments =
                            "${input.absolutePath} --release 1.0.0 --format cyclonedx -o ${target.toAbsolutePath()}"
                        VexCommand().test(arguments).statusCode shouldBe 0
                        val firstContent = target.readText()

                        val result = VexCommand().test(arguments)

                        result.statusCode shouldBe 0
                        result.stderr shouldContain "Unchanged: ${target.toAbsolutePath()}"
                        target.readText() shouldBe firstContent
                    }
                }
            }

            test("a rerun with changed statements keeps the serial number and bumps the version") {
                withTempDir(prefix = "vex-out") { outputDir ->
                    val target = outputDir.resolve("vex.cdx.json")
                    withTempFile(content = vulnlogYamlWithPurls()) { input ->
                        VexCommand()
                            .test(
                                "${input.absolutePath} --release 1.0.0 --format cyclonedx -o ${target.toAbsolutePath()}",
                            ).statusCode shouldBe 0
                    }
                    val serialNumber =
                        Regex("\"serialNumber\": \"([^\"]+)\"").find(target.readText())!!.groupValues[1]

                    withTempFile(content = vulnlogYamlWithPurls(cveId = "CVE-2026-5678")) { input ->
                        val result =
                            VexCommand().test(
                                "${input.absolutePath} --release 1.0.0 --format cyclonedx -o ${target.toAbsolutePath()}",
                            )

                        result.statusCode shouldBe 0
                        val content = target.readText()
                        content shouldContain "\"serialNumber\": \"$serialNumber\""
                        content shouldContain "\"version\": 2"
                        content shouldContain "CVE-2026-5678"
                    }
                }
            }
        }

        context("failure paths") {

            test("rejects an unknown release") {
                withTempFile(content = vulnlogYamlWithPurls()) { input ->
                    val result = VexCommand().test("${input.absolutePath} --release 9.9.9 --format cyclonedx -o -")

                    result.statusCode shouldBe ExitCode.INVALID_FLAG_VALUE.code
                    result.stderr shouldContain "Release not found: 9.9.9"
                    result.stderr shouldContain "Known releases: 1.0.0"
                }
            }

            test("fails when the target release declares no purls") {
                withTempFile(content = vulnlogYaml()) { input ->
                    val result = VexCommand().test("${input.absolutePath} --release 1.0.0 --format cyclonedx -o -")

                    result.statusCode shouldBe ExitCode.VALIDATION_ERROR.code
                    result.stderr shouldContain "error: release '1.0.0' declares no purls"
                    result.stderr shouldContain "hint: add at least one purl"
                }
            }

            test("requires the format flag") {
                withTempFile(content = vulnlogYamlWithPurls()) { input ->
                    val result = VexCommand().test("${input.absolutePath} --release 1.0.0 -o -")

                    result.statusCode shouldNotBe 0
                    result.stderr shouldContain "--format"
                }
            }

            test("rejects an unknown format value") {
                withTempFile(content = vulnlogYamlWithPurls()) { input ->
                    val result = VexCommand().test("${input.absolutePath} --release 1.0.0 --format bogus -o -")

                    result.statusCode shouldNotBe 0
                    result.stderr shouldContain "--format"
                    result.stderr shouldContain "cyclonedx"
                }
            }

            test("requires the release flag") {
                withTempFile(content = vulnlogYamlWithPurls()) { input ->
                    val result = VexCommand().test("${input.absolutePath} --format cyclonedx -o -")

                    result.statusCode shouldNotBe 0
                    result.stderr shouldContain "--release"
                }
            }
        }
    })
