// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.openvex

import dev.vulnlog.lib.core.buildVexStatements
import dev.vulnlog.lib.model.Disposition
import dev.vulnlog.lib.model.Project
import dev.vulnlog.lib.model.Purl
import dev.vulnlog.lib.model.PurlEntry
import dev.vulnlog.lib.model.Release
import dev.vulnlog.lib.model.ReleaseEntry
import dev.vulnlog.lib.model.ReportEntry
import dev.vulnlog.lib.model.ReporterType
import dev.vulnlog.lib.model.Resolution
import dev.vulnlog.lib.model.SchemaVersion
import dev.vulnlog.lib.model.Severity
import dev.vulnlog.lib.model.Tag
import dev.vulnlog.lib.model.Verdict
import dev.vulnlog.lib.model.VexJustification
import dev.vulnlog.lib.model.VulnId
import dev.vulnlog.lib.model.VulnerabilityEntry
import dev.vulnlog.lib.model.VulnlogFile
import java.time.Instant
import java.time.LocalDate

internal val release1 = Release("1.0.0")
internal val release2 = Release("2.0.0")
internal val release3 = Release("3.0.0")
internal val productPurl = Purl.Generic("pkg:generic/example@2.0.0")
internal val packagePurl = Purl.Maven("pkg:maven/com.example/lib@1.0")

internal val project = Project(organization = "Example Org", name = "example", author = "Sec Team")

internal const val DOCUMENT_ID = "https://vulnlog.dev/vex/3e671687-395b-41f5-a30f-a58921a69b79"
internal const val TOOL_VERSION = "1.2.3"
internal val timestamp: Instant = Instant.parse("2026-04-25T00:00:00Z")

internal fun vulnerability(
    id: VulnId,
    aliases: List<VulnId> = emptyList(),
    description: String? = null,
    verdict: Verdict,
    resolution: Resolution? = null,
    analysis: String? = null,
    analyzedAt: LocalDate? = null,
    packages: List<Purl> = listOf(packagePurl),
    reports: List<ReportEntry> = emptyList(),
    tags: List<Tag> = emptyList(),
) = VulnerabilityEntry(
    id = id,
    aliases = aliases,
    description = description,
    releases = listOf(release1),
    packages = packages,
    reports = reports,
    tags = tags,
    analysis = analysis,
    analyzedAt = analyzedAt,
    verdict = verdict,
    resolution = resolution,
)

/** One vulnerability per OpenVEX status and action variant, targeting [release2]. */
internal val vulnlogFile =
    VulnlogFile(
        schemaVersion = SchemaVersion(1, 0),
        project = project,
        releases =
            listOf(
                ReleaseEntry(id = release1),
                ReleaseEntry(id = release2, purls = listOf(PurlEntry(productPurl, tags = listOf(Tag("cli"))))),
                ReleaseEntry(id = release3),
            ),
        vulnerabilities =
            listOf(
                vulnerability(
                    id = VulnId.Cve("CVE-2026-0001"),
                    aliases = listOf(VulnId.Ghsa("GHSA-2m67-wjpj-xhg9")),
                    description = "Allocation of resources without limits in example-lib.",
                    verdict = Verdict.NotAffected(VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH),
                    analysis = "The vulnerable method is not called.",
                    analyzedAt = LocalDate.of(2026, 4, 7),
                    reports = listOf(ReportEntry(reporter = ReporterType.TRIVY, at = LocalDate.of(2026, 4, 6))),
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
                vulnerability(
                    id = VulnId.Cve("CVE-2026-0005"),
                    verdict = Verdict.Affected(Severity.LOW, Disposition.WONT_FIX),
                    analysis = "The risk is accepted.",
                ),
                vulnerability(
                    id = VulnId.Cve("CVE-2026-0006"),
                    verdict = Verdict.Affected(Severity.MEDIUM),
                    resolution = Resolution(release = release3, note = "Bumped lib to 2.0."),
                ),
                vulnerability(
                    id = VulnId.Cve("CVE-2026-0007"),
                    verdict = Verdict.NotAffected(VexJustification.COMPONENT_NOT_PRESENT),
                    tags = listOf(Tag("docs")),
                ),
            ),
    )

internal fun writeDocument(): String {
    val statements = buildVexStatements(vulnlogFile, release2)
    val document =
        OpenVexMapper.toDto(
            project = project,
            statements = statements,
            documentId = DOCUMENT_ID,
            version = 1,
            timestamp = timestamp,
            lastUpdated = null,
            toolVersion = TOOL_VERSION,
        )
    return OpenVexWriter.write(document)
}
