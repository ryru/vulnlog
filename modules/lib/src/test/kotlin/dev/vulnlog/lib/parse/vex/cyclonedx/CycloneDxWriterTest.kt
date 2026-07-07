// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.cyclonedx

import dev.vulnlog.lib.core.buildVexStatements
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

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
        },
        {
          "id": "CVE-2026-0004",
          "analysis": {
            "state": "resolved"
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
        test("writes the standalone V1 document covering every analysis state") {
            writeDocument() shouldBe goldenDocument
        }

        test("writing the same inputs twice is byte-identical") {
            writeDocument() shouldBe writeDocument()
        }

        test("a package purl shared by several vulnerabilities appears once in components") {
            val statements = buildVexStatements(vulnlogFile, release2)

            val bom =
                CycloneDxMapper.toDto(project, vulnlogFile.releases[1], statements, SERIAL_NUMBER, 1, timestamp)

            bom.components.count { it.bomRef == packagePurl.value } shouldBe 1
        }
    })
