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
import java.time.Instant

internal val release1 = Release("1.0.0")
internal val release2 = Release("2.0.0")
internal val productPurl = Purl.Generic("pkg:generic/example@2.0.0")
internal val packagePurl = Purl.Maven("pkg:maven/com.example/lib@1.0")

internal val project = Project(organization = "Example Org", name = "example", author = "Sec Team")

internal const val SERIAL_NUMBER = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
internal val timestamp: Instant = Instant.parse("2026-04-25T00:00:00Z")

internal fun vulnerability(
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

/** One vulnerability per CycloneDX analysis state, targeting [release2]. */
internal val vulnlogFile =
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
                vulnerability(
                    id = VulnId.Cve("CVE-2026-0004"),
                    verdict = Verdict.Affected(Severity.MEDIUM),
                    resolution = Resolution(release = release2),
                ),
            ),
    )

internal fun writeDocument(): String {
    val statements = buildVexStatements(vulnlogFile, release2)
    val bom = CycloneDxMapper.toDto(project, vulnlogFile.releases[1], statements, SERIAL_NUMBER, 1, timestamp)
    return CycloneDxWriter.write(bom)
}
