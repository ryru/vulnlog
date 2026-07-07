// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.core

import dev.vulnlog.lib.model.Project
import dev.vulnlog.lib.model.Purl
import dev.vulnlog.lib.model.PurlEntry
import dev.vulnlog.lib.model.Release
import dev.vulnlog.lib.model.ReleaseEntry
import dev.vulnlog.lib.model.Resolution
import dev.vulnlog.lib.model.SchemaVersion
import dev.vulnlog.lib.model.Severity
import dev.vulnlog.lib.model.Tag
import dev.vulnlog.lib.model.Verdict
import dev.vulnlog.lib.model.VexJustification
import dev.vulnlog.lib.model.VulnId
import dev.vulnlog.lib.model.VulnerabilityEntry
import dev.vulnlog.lib.model.VulnlogFile
import dev.vulnlog.lib.model.vex.VexStatus
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe

private val release1 = Release("1.0.0")
private val release2 = Release("2.0.0")
private val release3 = Release("3.0.0")

private val productPurl = Purl.Generic("pkg:generic/product@2.0.0")
private val packagePurl = Purl.Maven("pkg:maven/com.example/lib@1.0")

private fun vulnlogFile(
    releases: List<ReleaseEntry>,
    vulnerabilities: List<VulnerabilityEntry>,
) = VulnlogFile(
    schemaVersion = SchemaVersion(1, 0),
    project = Project("org", "project", "author"),
    releases = releases,
    vulnerabilities = vulnerabilities,
)

private fun releaseEntry(
    release: Release,
    purls: List<Purl> = listOf(productPurl),
) = ReleaseEntry(id = release, purls = purls.map { PurlEntry(it) })

private fun vulnerability(
    id: VulnId = VulnId.Cve("CVE-2026-0001"),
    releases: List<Release> = listOf(release1),
    verdict: Verdict = Verdict.Affected(Severity.HIGH),
    resolution: Resolution? = null,
    analysis: String? = null,
    packages: List<Purl> = listOf(packagePurl),
    tags: List<Tag> = emptyList(),
) = VulnerabilityEntry(
    id = id,
    releases = releases,
    packages = packages,
    reports = emptyList(),
    tags = tags,
    analysis = analysis,
    verdict = verdict,
    resolution = resolution,
)

class VexStatementsTest :
    FunSpec({
        val threeReleases = listOf(releaseEntry(release1), releaseEntry(release2), releaseEntry(release3))

        test("a vulnerability recorded against an older release produces a statement for a later target") {
            val file = vulnlogFile(threeReleases, listOf(vulnerability(releases = listOf(release1))))

            val statements = buildVexStatements(file, release3)

            statements shouldHaveSize 1
        }

        test("a vulnerability recorded only against a newer release is excluded") {
            val file = vulnlogFile(threeReleases, listOf(vulnerability(releases = listOf(release2))))

            val statements = buildVexStatements(file, release1)

            statements.shouldBeEmpty()
        }

        test("an affected vulnerability without resolution stays affected") {
            val file = vulnlogFile(threeReleases, listOf(vulnerability()))

            val statements = buildVexStatements(file, release2)

            statements.first().status shouldBe VexStatus.Affected
        }

        test("an affected vulnerability is fixed once the target contains the resolution") {
            val entry = vulnerability(resolution = Resolution(release = release2))
            val file = vulnlogFile(threeReleases, listOf(entry))

            buildVexStatements(file, release1).first().status shouldBe VexStatus.Affected
            buildVexStatements(file, release2).first().status shouldBe VexStatus.Fixed
            buildVexStatements(file, release3).first().status shouldBe VexStatus.Fixed
        }

        test("a risk acceptable vulnerability stays affected even when a resolution exists") {
            val entry =
                vulnerability(
                    verdict = Verdict.RiskAcceptable(Severity.LOW),
                    resolution = Resolution(release = release2),
                )
            val file = vulnlogFile(threeReleases, listOf(entry))

            buildVexStatements(file, release3).first().status shouldBe VexStatus.Affected
        }

        test("a not affected vulnerability carries its justification") {
            val entry = vulnerability(verdict = Verdict.NotAffected(VexJustification.COMPONENT_NOT_PRESENT))
            val file = vulnlogFile(threeReleases, listOf(entry))

            val status = buildVexStatements(file, release1).first().status

            status shouldBe VexStatus.NotAffected(VexJustification.COMPONENT_NOT_PRESENT)
        }

        test("a vulnerability without verdict is under investigation") {
            val entry = vulnerability(verdict = Verdict.UnderInvestigation)
            val file = vulnlogFile(threeReleases, listOf(entry))

            buildVexStatements(file, release1).first().status shouldBe VexStatus.UnderInvestigation
        }

        test("statements carry the analysis text, target release purls, and sorted packages") {
            val purlA = Purl.Maven("pkg:maven/com.example/a@1.0")
            val purlB = Purl.Maven("pkg:maven/com.example/b@1.0")
            val entry = vulnerability(analysis = "the code path is unused", packages = listOf(purlB, purlA))
            val file = vulnlogFile(threeReleases, listOf(entry))

            val statement = buildVexStatements(file, release1).first()

            statement.detail shouldBe "the code path is unused"
            statement.products shouldBe listOf(productPurl)
            statement.packages shouldBe listOf(purlA, purlB)
        }

        test("statements are sorted by vulnerability id") {
            val file =
                vulnlogFile(
                    threeReleases,
                    listOf(
                        vulnerability(id = VulnId.Snyk("SNYK-JAVA-B-2")),
                        vulnerability(id = VulnId.Cve("CVE-2026-0002")),
                    ),
                )

            val statements = buildVexStatements(file, release1)

            statements.map { it.id.id } shouldBe listOf("CVE-2026-0002", "SNYK-JAVA-B-2")
        }

        test("a tagged vulnerability includes matching and untagged purls only") {
            val cliPurl = Purl.Generic("pkg:generic/product-cli@1.0.0")
            val pluginPurl = Purl.Generic("pkg:generic/product-plugin@1.0.0")
            val untaggedPurl = Purl.Generic("pkg:generic/product@1.0.0")
            val release =
                ReleaseEntry(
                    id = release1,
                    purls =
                        listOf(
                            PurlEntry(cliPurl, tags = listOf(Tag("cli"))),
                            PurlEntry(pluginPurl, tags = listOf(Tag("gradle plugin"))),
                            PurlEntry(untaggedPurl),
                        ),
                )
            val entry = vulnerability(tags = listOf(Tag("cli")))
            val file = vulnlogFile(listOf(release), listOf(entry))

            val statement = buildVexStatements(file, release1).first()

            statement.products shouldBe listOf(cliPurl, untaggedPurl)
        }

        test("an untagged vulnerability includes every purl") {
            val cliPurl = Purl.Generic("pkg:generic/product-cli@1.0.0")
            val pluginPurl = Purl.Generic("pkg:generic/product-plugin@1.0.0")
            val release =
                ReleaseEntry(
                    id = release1,
                    purls =
                        listOf(
                            PurlEntry(cliPurl, tags = listOf(Tag("cli"))),
                            PurlEntry(pluginPurl, tags = listOf(Tag("gradle plugin"))),
                        ),
                )
            val file = vulnlogFile(listOf(release), listOf(vulnerability()))

            val statement = buildVexStatements(file, release1).first()

            statement.products shouldBe listOf(cliPurl, pluginPurl)
        }

        test("an undefined target release is rejected") {
            val file = vulnlogFile(threeReleases, listOf(vulnerability()))

            shouldThrow<IllegalArgumentException> {
                buildVexStatements(file, Release("9.9.9"))
            }
        }
    })
