// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.cyclonedx

import dev.vulnlog.lib.core.buildVexStatements
import dev.vulnlog.lib.model.Project
import dev.vulnlog.lib.model.Purl
import dev.vulnlog.lib.model.PurlEntry
import dev.vulnlog.lib.model.Release
import dev.vulnlog.lib.model.ReleaseEntry
import dev.vulnlog.lib.model.Resolution
import dev.vulnlog.lib.model.SchemaVersion
import dev.vulnlog.lib.model.Severity
import dev.vulnlog.lib.model.Verdict
import dev.vulnlog.lib.model.VexJustification
import dev.vulnlog.lib.model.VulnId
import dev.vulnlog.lib.model.VulnerabilityEntry
import dev.vulnlog.lib.model.VulnlogFile
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.time.Instant

private val release1 = Release("1.0.0")
private val release2 = Release("2.0.0")
private val productPurl = Purl.Generic("pkg:generic/example@2.0.0")
private val packagePurl = Purl.Maven("pkg:maven/com.example/lib@1.0")

private val project = Project(organization = "Example Org", name = "example", author = "Sec Team")

private fun vulnerability(
    id: VulnId,
    verdict: Verdict,
    resolution: Resolution? = null,
    analysis: String? = null,
    packages: List<Purl> = listOf(packagePurl),
) = VulnerabilityEntry(
    id = id,
    releases = listOf(release1),
    packages = packages,
    reports = emptyList(),
    analysis = analysis,
    verdict = verdict,
    resolution = resolution,
)

private val vulnlogFile =
    VulnlogFile(
        schemaVersion = SchemaVersion(1, 0),
        project = project,
        releases =
            listOf(
                ReleaseEntry(id = release1),
                ReleaseEntry(id = release2, purls = listOf(PurlEntry(productPurl))),
            ),
        vulnerabilities =
            listOf(
                vulnerability(
                    id = VulnId.Cve("CVE-2026-0001"),
                    verdict = Verdict.NotAffected(VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH),
                    analysis = "The vulnerable method is not called.",
                ),
                vulnerability(
                    id = VulnId.Cve("CVE-2026-0002"),
                    verdict = Verdict.Affected(Severity.HIGH),
                ),
                vulnerability(
                    id = VulnId.Cve("CVE-2026-0003"),
                    verdict = Verdict.UnderInvestigation,
                ),
            ),
    )

private const val SERIAL_NUMBER = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
private val timestamp = Instant.parse("2026-04-25T00:00:00Z")

private fun writeDocument(): String {
    val statements = buildVexStatements(vulnlogFile, release2)
    val bom = CycloneDxMapper.toDto(project, vulnlogFile.releases[1], statements, SERIAL_NUMBER, 1, timestamp)
    return CycloneDxWriter.write(bom)
}

private val goldenDocument =
    """
    {
      "bomFormat": "CycloneDX",
      "specVersion": "1.7",
      "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
      "version": 1,
      "metadata": {
        "timestamp": "2026-04-25T00:00:00Z",
        "component": {
          "bom-ref": "example@2.0.0",
          "type": "application",
          "name": "example",
          "version": "2.0.0"
        }
      },
      "components": [
        {
          "bom-ref": "pkg:generic/example@2.0.0",
          "type": "application",
          "name": "example",
          "version": "2.0.0"
        },
        {
          "bom-ref": "pkg:maven/com.example/lib@1.0",
          "type": "library",
          "name": "lib",
          "version": "1.0"
        }
      ],
      "vulnerabilities": [
        {
          "id": "CVE-2026-0001",
          "analysis": {
            "state": "not_affected",
            "justification": "code_not_reachable",
            "detail": "The vulnerable method is not called."
          },
          "affects": [
            {
              "ref": "pkg:generic/example@2.0.0"
            }
          ]
        },
        {
          "id": "CVE-2026-0002",
          "analysis": {
            "state": "exploitable"
          },
          "affects": [
            {
              "ref": "pkg:generic/example@2.0.0"
            }
          ]
        },
        {
          "id": "CVE-2026-0003",
          "analysis": {
            "state": "in_triage"
          },
          "affects": [
            {
              "ref": "pkg:generic/example@2.0.0"
            }
          ]
        }
      ]
    }

    """.trimIndent()

class CycloneDxWriterTest :
    FunSpec({
        test("writes the standalone V1 document") {
            writeDocument() shouldBe goldenDocument
        }

        test("writing the same inputs twice is byte-identical") {
            writeDocument() shouldBe writeDocument()
        }

        test("a fixed vulnerability is emitted as resolved") {
            val entry =
                vulnerability(
                    id = VulnId.Cve("CVE-2026-0004"),
                    verdict = Verdict.Affected(Severity.HIGH),
                    resolution = Resolution(release = release2),
                )
            val file = vulnlogFile.copy(vulnerabilities = listOf(entry))

            val statements = buildVexStatements(file, release2)
            val bom = CycloneDxMapper.toDto(project, file.releases[1], statements, SERIAL_NUMBER, 1, timestamp)

            CycloneDxWriter.write(bom) shouldContain "\"state\": \"resolved\""
        }

        test("a package purl shared by several vulnerabilities appears once in components") {
            val statements = buildVexStatements(vulnlogFile, release2)
            val bom = CycloneDxMapper.toDto(project, vulnlogFile.releases[1], statements, SERIAL_NUMBER, 1, timestamp)

            bom.components.count { it.bomRef == packagePurl.value } shouldBe 1
        }
    })
