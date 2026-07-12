// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.cli.shell

import com.github.ajalt.clikt.testing.test
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlin.io.path.readText

/**
 * Builds a Vulnlog YAML whose only vulnerability concerns a later release, so that the target
 * release yields no statements.
 */
private fun vulnlogYamlVulnOnLaterRelease(): String =
    """
    ---
    schemaVersion: "1"

    project:
      organization: Acme Corp
      name: Acme Web App
      author: Acme Corp Security Team

    releases:
      - id: 1.0.0
        published_at: 2026-01-15
        purls:
          - purl: "pkg:generic/acme-web-app@1.0.0"
      - id: 2.0.0

    vulnerabilities:

      - id: CVE-2026-1234
        releases: [ 2.0.0 ]
        packages: [ "pkg:npm/example-lib@2.3.0" ]
        reports:
          - reporter: trivy
    """.trimIndent()

class VexCommandTest :
    FunSpec({

        context("happy path") {

            test("writes an OpenVEX document to the user-specified path") {
                withTempFile(content = vulnlogYamlWithPurls()) { input ->
                    withTempDir(prefix = "vex-out") { outputDir ->
                        val target = outputDir.resolve("vex.json")

                        val result =
                            VexCommand().test(
                                "${input.absolutePath} --release 1.0.0 -o ${target.toAbsolutePath()}",
                            )

                        result.statusCode shouldBe 0
                        result.stderr shouldContain "Wrote: ${target.toAbsolutePath()}"
                        val content = target.readText()
                        content shouldContain "\"@context\": \"https://openvex.dev/ns/v0.2.0\""
                        content shouldContain "\"author\": \"Acme Corp Security Team\""
                        content shouldContain "CVE-2026-1234"
                        content shouldContain "\"status\": \"not_affected\""
                        content shouldContain "\"justification\": \"vulnerable_code_not_in_execute_path\""
                        content shouldContain "\"@id\": \"pkg:generic/acme-web-app@1.0.0\""
                        content shouldContain "\"@id\": \"pkg:npm/example-lib@2.3.0\""
                    }
                }
            }

            test("accepts the explicit openvex format") {
                withTempFile(content = vulnlogYamlWithPurls()) { input ->
                    val result = VexCommand().test("${input.absolutePath} --release 1.0.0 --format openvex -o -")

                    result.statusCode shouldBe 0
                    result.stdout shouldContain "\"@context\": \"https://openvex.dev/ns/v0.2.0\""
                }
            }

            test("writes to stdout when -o is '-'") {
                withTempFile(content = vulnlogYamlWithPurls()) { input ->
                    val result = VexCommand().test("${input.absolutePath} --release 1.0.0 -o -")

                    result.statusCode shouldBe 0
                    result.stdout shouldContain "\"@context\": \"https://openvex.dev/ns/v0.2.0\""
                }
            }

            test("a rerun against its own output as baseline reports the output as unchanged") {
                withTempFile(content = vulnlogYamlWithPurls()) { input ->
                    withTempDir(prefix = "vex-out") { outputDir ->
                        val target = outputDir.resolve("vex.json")
                        VexCommand()
                            .test("${input.absolutePath} --release 1.0.0 -o ${target.toAbsolutePath()}")
                            .statusCode shouldBe 0
                        val firstContent = target.readText()

                        val result =
                            VexCommand().test(
                                "${input.absolutePath} --release 1.0.0 " +
                                    "--baseline ${target.toAbsolutePath()} -o ${target.toAbsolutePath()}",
                            )

                        result.statusCode shouldBe 0
                        result.stderr shouldContain "Unchanged: ${target.toAbsolutePath()}"
                        target.readText() shouldBe firstContent
                    }
                }
            }

            test("an unchanged document is still written when the output differs from the baseline") {
                withTempFile(content = vulnlogYamlWithPurls()) { input ->
                    withTempDir(prefix = "vex-out") { outputDir ->
                        val baseline = outputDir.resolve("vex.json")
                        VexCommand()
                            .test("${input.absolutePath} --release 1.0.0 -o ${baseline.toAbsolutePath()}")
                            .statusCode shouldBe 0
                        val target = outputDir.resolve("copy.json")

                        val result =
                            VexCommand().test(
                                "${input.absolutePath} --release 1.0.0 " +
                                    "--baseline ${baseline.toAbsolutePath()} -o ${target.toAbsolutePath()}",
                            )

                        result.statusCode shouldBe 0
                        result.stderr shouldContain "Wrote: ${target.toAbsolutePath()}"
                        target.readText() shouldBe baseline.readText()
                    }
                }
            }

            test("a rerun with a baseline and changed statements keeps the identity and bumps the version") {
                withTempDir(prefix = "vex-out") { outputDir ->
                    val target = outputDir.resolve("vex.json")
                    withTempFile(content = vulnlogYamlWithPurls()) { input ->
                        VexCommand()
                            .test("${input.absolutePath} --release 1.0.0 -o ${target.toAbsolutePath()}")
                            .statusCode shouldBe 0
                    }
                    val firstContent = target.readText()
                    val documentId = Regex("\"@id\": \"(https[^\"]+)\"").find(firstContent)!!.groupValues[1]
                    val timestamp = Regex("\"timestamp\": \"([^\"]+)\"").find(firstContent)!!.groupValues[1]

                    withTempFile(content = vulnlogYamlWithPurls(cveId = "CVE-2026-5678")) { input ->
                        val result =
                            VexCommand().test(
                                "${input.absolutePath} --release 1.0.0 " +
                                    "--baseline ${target.toAbsolutePath()} -o ${target.toAbsolutePath()}",
                            )

                        result.statusCode shouldBe 0
                        val content = target.readText()
                        content shouldContain "\"@id\": \"$documentId\""
                        content shouldContain "\"timestamp\": \"$timestamp\""
                        content shouldContain "\"version\": 2"
                        content shouldContain "\"last_updated\""
                        content shouldContain "CVE-2026-5678"
                    }
                }
            }

            test("a rerun without a baseline starts a new identity even when the output exists") {
                withTempFile(content = vulnlogYamlWithPurls()) { input ->
                    withTempDir(prefix = "vex-out") { outputDir ->
                        val target = outputDir.resolve("vex.json")
                        val arguments = "${input.absolutePath} --release 1.0.0 -o ${target.toAbsolutePath()}"
                        VexCommand().test(arguments).statusCode shouldBe 0
                        val documentId = Regex("\"@id\": \"(https[^\"]+)\"").find(target.readText())!!.groupValues[1]

                        val result = VexCommand().test(arguments)

                        result.statusCode shouldBe 0
                        result.stderr shouldContain "Wrote: ${target.toAbsolutePath()}"
                        val content = target.readText()
                        content shouldContain "\"version\": 1"
                        content shouldNotContain "\"@id\": \"$documentId\""
                    }
                }
            }
        }

        context("all releases") {

            test("without --release the document covers every release that declares purls") {
                withTempFile(content = vulnlogYamlAcrossReleases()) { input ->
                    val result = VexCommand().test("${input.absolutePath} -o -")

                    result.statusCode shouldBe 0
                    result.stdout shouldContain "\"@id\": \"pkg:generic/acme-web-app@1.0.0\""
                    result.stdout shouldContain "\"@id\": \"pkg:generic/acme-web-app@2.0.0\""
                    result.stdout shouldContain "\"status\": \"affected\""
                    result.stdout shouldContain "\"status\": \"fixed\""
                }
            }

            test("releases without purls are named in a warning and left out") {
                withTempFile(content = vulnlogYamlAcrossReleases()) { input ->
                    val result = VexCommand().test("${input.absolutePath} -o -")

                    result.statusCode shouldBe 0
                    result.stderr shouldContain
                        "warning: releases without purls are not part of the document: '3.0.0'"
                }
            }

            test("fails when no release declares purls") {
                withTempFile(content = vulnlogYaml()) { input ->
                    val result = VexCommand().test("${input.absolutePath} -o -")

                    result.statusCode shouldBe ExitCode.VALIDATION_ERROR.code
                    result.stderr shouldContain "error: no release declares purls"
                    result.stderr shouldContain "hint: add at least one purl to a release"
                }
            }
        }

        context("tag scoping") {

            test("--tag narrows the products to the tagged purls") {
                withTempFile(content = vulnlogYamlWithTaggedPurls()) { input ->
                    val result =
                        VexCommand().test(
                            "${input.absolutePath} --release 1.0.0 --tag \"gradle plugin\" -o -",
                        )

                    result.statusCode shouldBe 0
                    result.stdout shouldContain "\"@id\": \"pkg:maven/com.acme/acme-plugin@1.0.0\""
                    result.stdout shouldNotContain "pkg:generic/acme-cli@1.0.0"
                }
            }

            test("a vulnerability outside the scope stays in the document with empty products") {
                withTempFile(content = vulnlogYamlWithTaggedPurls()) { input ->
                    val result = VexCommand().test("${input.absolutePath} --release 1.0.0 --tag cli -o -")

                    result.statusCode shouldBe 0
                    result.stdout shouldContain "CVE-2026-1234"
                    result.stdout shouldContain "\"products\": [ ]"
                    result.stdout shouldNotContain "pkg:maven/com.acme/acme-plugin@1.0.0"
                }
            }

            test("rejects an unknown tag") {
                withTempFile(content = vulnlogYamlWithTaggedPurls()) { input ->
                    val result = VexCommand().test("${input.absolutePath} --release 1.0.0 --tag bogus -o -")

                    result.statusCode shouldBe ExitCode.INVALID_FLAG_VALUE.code
                    result.stderr shouldContain "Tag not found: bogus"
                    result.stderr shouldContain "Known tags:"
                }
            }

            test("fails when no purl carries the requested tag") {
                withTempFile(content = vulnlogYamlWithTaggedPurls()) { input ->
                    val result = VexCommand().test("${input.absolutePath} --release 1.0.0 --tag container -o -")

                    result.statusCode shouldBe ExitCode.VALIDATION_ERROR.code
                    result.stderr shouldContain "error: release '1.0.0' declares no purls tagged 'container'"
                    result.stderr shouldContain "hint: tag a purl"
                }
            }
        }

        context("failure paths") {

            test("rejects an unknown release") {
                withTempFile(content = vulnlogYamlWithPurls()) { input ->
                    val result = VexCommand().test("${input.absolutePath} --release 9.9.9 -o -")

                    result.statusCode shouldBe ExitCode.INVALID_FLAG_VALUE.code
                    result.stderr shouldContain "Release not found: 9.9.9"
                    result.stderr shouldContain "Known releases: 1.0.0"
                }
            }

            test("fails when the target release declares no purls") {
                withTempFile(content = vulnlogYaml()) { input ->
                    val result = VexCommand().test("${input.absolutePath} --release 1.0.0 -o -")

                    result.statusCode shouldBe ExitCode.VALIDATION_ERROR.code
                    result.stderr shouldContain "error: release '1.0.0' declares no purls"
                    result.stderr shouldContain "hint: add at least one purl"
                }
            }

            test("fails when the target release yields no statements") {
                withTempFile(content = vulnlogYamlVulnOnLaterRelease()) { input ->
                    val result = VexCommand().test("${input.absolutePath} --release 1.0.0 -o -")

                    result.statusCode shouldBe ExitCode.VALIDATION_ERROR.code
                    result.stderr shouldContain "error: release '1.0.0' has no vulnerabilities to state"
                    result.stderr shouldContain "hint: an OpenVEX document needs at least one statement"
                }
            }

            test("rejects a missing baseline file") {
                withTempFile(content = vulnlogYamlWithPurls()) { input ->
                    val result =
                        VexCommand().test("${input.absolutePath} --release 1.0.0 --baseline missing.json -o -")

                    result.statusCode shouldBe ExitCode.INVALID_FLAG_VALUE.code
                    result.stderr shouldContain "error: baseline file 'missing.json' does not exist"
                    result.stderr shouldContain "hint: point --baseline at an existing OpenVEX document"
                }
            }

            test("rejects an unknown format value") {
                withTempFile(content = vulnlogYamlWithPurls()) { input ->
                    val result = VexCommand().test("${input.absolutePath} --release 1.0.0 --format bogus -o -")

                    result.statusCode shouldNotBe 0
                    result.stderr shouldContain "--format"
                    result.stderr shouldContain "openvex"
                }
            }
        }
    })
