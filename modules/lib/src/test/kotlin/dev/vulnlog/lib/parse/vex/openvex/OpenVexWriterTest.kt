// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.openvex

import dev.vulnlog.lib.core.buildVexStatements
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

private val goldenDocument =
    """
    {
      "@context": "https://openvex.dev/ns/v0.2.0",
      "@id": "https://vulnlog.dev/vex/3e671687-395b-41f5-a30f-a58921a69b79",
      "author": "Sec Team",
      "role": "Document Creator",
      "timestamp": "2026-04-25T00:00:00Z",
      "version": 1,
      "tooling": "vulnlog/1.2.3",
      "statements": [
        {
          "vulnerability": {
            "@id": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
            "name": "CVE-2026-0001",
            "description": "Allocation of resources without limits in example-lib.",
            "aliases": [
              "GHSA-2m67-wjpj-xhg9"
            ]
          },
          "timestamp": "2026-04-07T00:00:00Z",
          "products": [
            {
              "@id": "pkg:generic/example@2.0.0",
              "identifiers": {
                "purl": "pkg:generic/example@2.0.0"
              },
              "subcomponents": [
                {
                  "@id": "pkg:maven/com.example/lib@1.0"
                }
              ]
            }
          ],
          "status": "not_affected",
          "justification": "vulnerable_code_not_in_execute_path",
          "impact_statement": "The vulnerable method is not called.",
          "supplier": "Example Org"
        },
        {
          "vulnerability": {
            "@id": "https://nvd.nist.gov/vuln/detail/CVE-2026-0002",
            "name": "CVE-2026-0002"
          },
          "timestamp": "2026-04-25T00:00:00Z",
          "products": [
            {
              "@id": "pkg:generic/example@2.0.0",
              "identifiers": {
                "purl": "pkg:generic/example@2.0.0"
              },
              "subcomponents": [
                {
                  "@id": "pkg:maven/com.example/lib@1.0"
                }
              ]
            }
          ],
          "status": "affected",
          "action_statement": "No remediation is available yet.",
          "action_statement_timestamp": "2026-04-25T00:00:00Z",
          "supplier": "Example Org"
        },
        {
          "vulnerability": {
            "@id": "https://nvd.nist.gov/vuln/detail/CVE-2026-0003",
            "name": "CVE-2026-0003"
          },
          "timestamp": "2026-04-25T00:00:00Z",
          "products": [
            {
              "@id": "pkg:generic/example@2.0.0",
              "identifiers": {
                "purl": "pkg:generic/example@2.0.0"
              },
              "subcomponents": [
                {
                  "@id": "pkg:maven/com.example/lib@1.0"
                }
              ]
            }
          ],
          "status": "under_investigation",
          "supplier": "Example Org"
        },
        {
          "vulnerability": {
            "@id": "https://nvd.nist.gov/vuln/detail/CVE-2026-0004",
            "name": "CVE-2026-0004"
          },
          "timestamp": "2026-04-25T00:00:00Z",
          "products": [
            {
              "@id": "pkg:generic/example@2.0.0",
              "identifiers": {
                "purl": "pkg:generic/example@2.0.0"
              },
              "subcomponents": [
                {
                  "@id": "pkg:maven/com.example/lib@1.0"
                }
              ]
            }
          ],
          "status": "fixed",
          "supplier": "Example Org"
        },
        {
          "vulnerability": {
            "@id": "https://nvd.nist.gov/vuln/detail/CVE-2026-0005",
            "name": "CVE-2026-0005"
          },
          "timestamp": "2026-04-25T00:00:00Z",
          "products": [
            {
              "@id": "pkg:generic/example@2.0.0",
              "identifiers": {
                "purl": "pkg:generic/example@2.0.0"
              },
              "subcomponents": [
                {
                  "@id": "pkg:maven/com.example/lib@1.0"
                }
              ]
            }
          ],
          "status": "affected",
          "action_statement": "The risk is accepted. No fix is planned.",
          "action_statement_timestamp": "2026-04-25T00:00:00Z",
          "status_notes": "The risk is accepted.",
          "supplier": "Example Org"
        },
        {
          "vulnerability": {
            "@id": "https://nvd.nist.gov/vuln/detail/CVE-2026-0006",
            "name": "CVE-2026-0006"
          },
          "timestamp": "2026-04-25T00:00:00Z",
          "products": [
            {
              "@id": "pkg:generic/example@2.0.0",
              "identifiers": {
                "purl": "pkg:generic/example@2.0.0"
              },
              "subcomponents": [
                {
                  "@id": "pkg:maven/com.example/lib@1.0"
                }
              ]
            }
          ],
          "status": "affected",
          "action_statement": "Update to release 3.0.0. Bumped lib to 2.0.",
          "action_statement_timestamp": "2026-04-25T00:00:00Z",
          "supplier": "Example Org"
        },
        {
          "vulnerability": {
            "@id": "https://nvd.nist.gov/vuln/detail/CVE-2026-0007",
            "name": "CVE-2026-0007"
          },
          "timestamp": "2026-04-25T00:00:00Z",
          "products": [ ],
          "status": "not_affected",
          "justification": "component_not_present",
          "supplier": "Example Org"
        }
      ]
    }
    """.trimIndent() + "\n"

class OpenVexWriterTest :
    FunSpec({
        test("writes the golden document for one vulnerability per status and action variant") {
            writeDocument() shouldBe goldenDocument
        }

        test("emits last_updated when the caller provides an update time") {
            val statements = buildVexStatements(vulnlogFile, release2)
            val document =
                OpenVexMapper.toDto(
                    project = project,
                    statements = statements,
                    documentId = DOCUMENT_ID,
                    version = 2,
                    timestamp = timestamp,
                    lastUpdated = timestamp.plusSeconds(86400),
                    toolVersion = TOOL_VERSION,
                )

            val content = OpenVexWriter.write(document)

            content shouldContain "\"last_updated\": \"2026-04-26T00:00:00Z\""
            content shouldContain "\"version\": 2"
        }
    })
