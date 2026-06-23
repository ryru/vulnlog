// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse

import dev.vulnlog.lib.model.ParseValidationVersion
import dev.vulnlog.lib.model.SchemaVersion
import dev.vulnlog.lib.model.Severity
import dev.vulnlog.lib.model.Verdict
import dev.vulnlog.lib.model.VexJustification
import dev.vulnlog.lib.model.VulnId
import dev.vulnlog.lib.model.VulnlogFileRaw
import dev.vulnlog.lib.result.ParseResult
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf

class YamlParserTest :
    FunSpec({

        val parser = YamlParser(createYamlMapper())

        context("syntactic stage") {
            test("malformed yaml returns an error with a source location") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1"
                        project: [unterminated
                        """.trimIndent(),
                    )

                val error = parser.parse(yaml).shouldBeInstanceOf<ParseResult.Error>()
                error.location.shouldNotBeNull().line shouldBe 2
            }

            test("missing colon points at the offending key, not where the scanner choked") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1"
                        vulnerabilities
                          - id: CVE-2021-1
                        """.trimIndent(),
                    )

                // `vulnerabilities` (line 2) is missing its colon; the scanner only fails on line 3.
                val error = parser.parse(yaml).shouldBeInstanceOf<ParseResult.Error>()
                error.location.shouldNotBeNull().line shouldBe 2
            }

            test("stray key is reported as an unknown field at its own line") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1"
                        project:
                          organization: acme
                          name: widget
                          author: alice
                        releases: []
                        vulnerabilities: []
                        bogus: 1
                        """.trimIndent(),
                    )

                val error = parser.parse(yaml).shouldBeInstanceOf<ParseResult.Error>()
                error.error shouldContain "Unknown field 'bogus'"
                error.error shouldContain "'vulnerabilities'"
                error.location.shouldNotBeNull().line shouldBe 8
            }

            test("misspelling a required key reports the missing required field") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1"
                        project:
                          organization: acme
                          name: widget
                          author: alice
                        releases: []
                        vulnerabiities: []
                        """.trimIndent(),
                    )

                parser
                    .parse(yaml)
                    .shouldBeInstanceOf<ParseResult.Error>()
                    .error shouldContain "Missing required field 'vulnerabilities'"
            }

            test("missing field in a list entry points at that entry, not the next one") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1"
                        project:
                          organization: acme
                          name: widget
                          author: alice
                        releases: []
                        vulnerabilities:
                          - id: CVE-0001-001
                            releases: []
                          - id: CVE-0002-002
                            releases: []
                            packages: []
                            reports: []
                        """.trimIndent(),
                    )

                val error = parser.parse(yaml).shouldBeInstanceOf<ParseResult.Error>()
                error.error shouldContain "Missing required field 'packages'"
                // The CVE-0001-001 entry is on line 8; the error must not point at the next entry.
                error.location.shouldNotBeNull().line shouldBe 8
            }

            test("structural binding error carries a source location") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1"
                        project: "not an object"
                        releases: []
                        vulnerabilities: []
                        """.trimIndent(),
                    )

                parser
                    .parse(yaml)
                    .shouldBeInstanceOf<ParseResult.Error>()
                    .location
                    .shouldNotBeNull()
            }
        }

        context("schema version detection") {
            test("missing schemaVersion field returns an error") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        project:
                          organization: acme
                          name: widget
                          author: alice
                        releases: []
                        vulnerabilities: []
                        """.trimIndent(),
                    )

                parser
                    .parse(yaml)
                    .shouldBeInstanceOf<ParseResult.Error>()
                    .error shouldContain "schemaVersion"
            }

            test("non-numeric schemaVersion returns an error") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "abc"
                        project:
                          organization: acme
                          name: widget
                          author: alice
                        releases: []
                        vulnerabilities: []
                        """.trimIndent(),
                    )

                parser.parse(yaml).shouldBeInstanceOf<ParseResult.Error>()
            }

            test("unsupported major version returns an error mentioning the version") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "99"
                        project:
                          organization: acme
                          name: widget
                          author: alice
                        releases: []
                        vulnerabilities: []
                        """.trimIndent(),
                    )

                parser
                    .parse(yaml)
                    .shouldBeInstanceOf<ParseResult.Error>()
                    .error shouldContain "99"
            }
        }

        context("v1 parsing") {
            test("minimal valid v1 file parses project fields") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1"
                        project:
                          organization: acme
                          name: widget
                          author: alice
                        releases: []
                        vulnerabilities: []
                        """.trimIndent(),
                    )

                val ok = parser.parse(yaml).shouldBeInstanceOf<ParseResult.Ok>()
                ok.validationVersion shouldBe ParseValidationVersion.V1
                ok.content.schemaVersion shouldBe SchemaVersion(1, 0)
                ok.content.project.organization shouldBe "acme"
                ok.content.project.name shouldBe "widget"
                ok.content.project.author shouldBe "alice"
            }

            test("v1.2 file parses with correct minor version") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1.2"
                        project:
                          organization: acme
                          name: widget
                          author: alice
                        releases: []
                        vulnerabilities: []
                        """.trimIndent(),
                    )

                parser
                    .parse(yaml)
                    .shouldBeInstanceOf<ParseResult.Ok>()
                    .content.schemaVersion shouldBe SchemaVersion(1, 2)
            }

            test("release entries are parsed by id") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1"
                        project:
                          organization: acme
                          name: widget
                          author: alice
                        releases:
                          - id: "v1.0"
                          - id: "v2.0"
                        vulnerabilities: []
                        """.trimIndent(),
                    )

                val releases =
                    parser
                        .parse(yaml)
                        .shouldBeInstanceOf<ParseResult.Ok>()
                        .content.releases
                releases shouldHaveSize 2
                releases[0].id.value shouldBe "v1.0"
                releases[1].id.value shouldBe "v2.0"
            }

            test("vulnerability with CVE id is parsed") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1"
                        project:
                          organization: acme
                          name: widget
                          author: alice
                        releases: []
                        vulnerabilities:
                          - id: CVE-2021-44228
                            releases: []
                            packages: []
                            reports:
                              - reporter: grype
                        """.trimIndent(),
                    )

                val vulns =
                    parser
                        .parse(yaml)
                        .shouldBeInstanceOf<ParseResult.Ok>()
                        .content.vulnerabilities
                vulns shouldHaveSize 1
                vulns[0].id shouldBe VulnId.Cve("CVE-2021-44228")
            }

            test("vulnerability without verdict defaults to under_investigation") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1"
                        project:
                          organization: acme
                          name: widget
                          author: alice
                        releases: []
                        vulnerabilities:
                          - id: CVE-2021-1234
                            releases: []
                            packages: []
                            reports: []
                        """.trimIndent(),
                    )

                parser
                    .parse(yaml)
                    .shouldBeInstanceOf<ParseResult.Ok>()
                    .content.vulnerabilities[0]
                    .verdict shouldBe Verdict.UnderInvestigation
            }

            test("vulnerability with affected verdict and severity is parsed") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1"
                        project:
                          organization: acme
                          name: widget
                          author: alice
                        releases: []
                        vulnerabilities:
                          - id: CVE-2021-1234
                            releases: []
                            packages: []
                            reports: []
                            verdict: affected
                            severity: high
                        """.trimIndent(),
                    )

                parser
                    .parse(yaml)
                    .shouldBeInstanceOf<ParseResult.Ok>()
                    .content.vulnerabilities[0]
                    .verdict shouldBe Verdict.Affected(Severity.HIGH)
            }

            test("vulnerability with not affected verdict and justification is parsed") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1"
                        project:
                          organization: acme
                          name: widget
                          author: alice
                        releases: []
                        vulnerabilities:
                          - id: CVE-2021-1234
                            releases: []
                            packages: []
                            reports: []
                            verdict: not affected
                            justification: component not present
                        """.trimIndent(),
                    )

                parser
                    .parse(yaml)
                    .shouldBeInstanceOf<ParseResult.Ok>()
                    .content.vulnerabilities[0]
                    .verdict shouldBe
                    Verdict.NotAffected(VexJustification.COMPONENT_NOT_PRESENT)
            }

            test("vulnerability with risk acceptable verdict and severity is parsed") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1"
                        project:
                          organization: acme
                          name: widget
                          author: alice
                        releases: []
                        vulnerabilities:
                          - id: CVE-2021-1234
                            releases: []
                            packages: []
                            reports: []
                            verdict: risk acceptable
                            severity: medium
                        """.trimIndent(),
                    )

                parser
                    .parse(yaml)
                    .shouldBeInstanceOf<ParseResult.Ok>()
                    .content.vulnerabilities[0]
                    .verdict shouldBe Verdict.RiskAcceptable(Severity.MEDIUM)
            }

            test("vulnerability with unrecognized id returns a parse error") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1"
                        project:
                          organization: acme
                          name: widget
                          author: alice
                        releases: []
                        vulnerabilities:
                          - id: UNKNOWN-2021-0001
                            releases: []
                            packages: []
                            reports: []
                        """.trimIndent(),
                    )

                parser.parse(yaml).shouldBeInstanceOf<ParseResult.Error>()
            }

            test("vulnerability with maven package purl is parsed") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1"
                        project:
                          organization: acme
                          name: widget
                          author: alice
                        releases: []
                        vulnerabilities:
                          - id: CVE-2021-44228
                            releases: []
                            packages:
                              - "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
                            reports: []
                        """.trimIndent(),
                    )

                val vulns =
                    parser
                        .parse(yaml)
                        .shouldBeInstanceOf<ParseResult.Ok>()
                        .content.vulnerabilities
                vulns[0].packages shouldHaveSize 1
            }

            test("project field of wrong type returns a parse error") {
                val yaml =
                    VulnlogFileRaw(
                        """
                        schemaVersion: "1"
                        project: "not an object"
                        releases: []
                        vulnerabilities: []
                        """.trimIndent(),
                    )

                parser.parse(yaml).shouldBeInstanceOf<ParseResult.Error>()
            }
        }
    })
