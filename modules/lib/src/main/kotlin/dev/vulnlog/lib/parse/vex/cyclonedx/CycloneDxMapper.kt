// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.cyclonedx

import com.github.packageurl.PackageURL
import dev.vulnlog.lib.core.toCycloneDxJustification
import dev.vulnlog.lib.core.toCycloneDxState
import dev.vulnlog.lib.model.Project
import dev.vulnlog.lib.model.Purl
import dev.vulnlog.lib.model.ReleaseEntry
import dev.vulnlog.lib.model.vex.VexStatement
import dev.vulnlog.lib.model.vex.VexStatus
import dev.vulnlog.lib.parse.vex.cyclonedx.dto.AffectsDto
import dev.vulnlog.lib.parse.vex.cyclonedx.dto.AnalysisDto
import dev.vulnlog.lib.parse.vex.cyclonedx.dto.BomDto
import dev.vulnlog.lib.parse.vex.cyclonedx.dto.ComponentDto
import dev.vulnlog.lib.parse.vex.cyclonedx.dto.MetadataDto
import dev.vulnlog.lib.parse.vex.cyclonedx.dto.VulnerabilityDto
import java.time.Instant
import java.time.temporal.ChronoUnit

private const val BOM_FORMAT = "CycloneDX"
private const val SPEC_VERSION = "1.7"
private const val TYPE_APPLICATION = "application"
private const val TYPE_LIBRARY = "library"

object CycloneDxMapper {
    /**
     * Assembles a standalone CycloneDX VEX document. The synthetic metadata component identifies the
     * target release; the release purls anchor the statements and the package purls give context.
     * Document identity ([serialNumber], [version]) is decided by the caller.
     */
    fun toDto(
        project: Project,
        release: ReleaseEntry,
        statements: List<VexStatement>,
        serialNumber: String,
        version: Int,
        timestamp: Instant,
    ): BomDto =
        BomDto(
            bomFormat = BOM_FORMAT,
            specVersion = SPEC_VERSION,
            serialNumber = serialNumber,
            version = version,
            metadata =
                MetadataDto(
                    timestamp = timestamp.truncatedTo(ChronoUnit.SECONDS).toString(),
                    component =
                        ComponentDto(
                            bomRef = "${project.name}@${release.id.value}",
                            type = TYPE_APPLICATION,
                            name = project.name,
                            version = release.id.value,
                        ),
                ),
            components = toComponents(release, statements),
            vulnerabilities = statements.map(::toVulnerability),
        )

    private fun toComponents(
        release: ReleaseEntry,
        statements: List<VexStatement>,
    ): List<ComponentDto> {
        val releaseComponents = release.purls.map { entry -> toComponent(entry.purl, TYPE_APPLICATION) }
        val packageComponents =
            statements
                .flatMap { statement -> statement.packages }
                .distinct()
                .map { purl -> toComponent(purl, TYPE_LIBRARY) }
        return (releaseComponents + packageComponents)
            .distinctBy { component -> component.bomRef }
            .sortedBy { component -> component.bomRef }
    }

    private fun toComponent(
        purl: Purl,
        type: String,
    ): ComponentDto {
        val parsed = PackageURL(purl.value)
        return ComponentDto(
            bomRef = purl.value,
            type = type,
            name = parsed.name,
            version = parsed.version,
        )
    }

    private fun toVulnerability(statement: VexStatement): VulnerabilityDto =
        VulnerabilityDto(
            id = statement.id.id,
            analysis =
                AnalysisDto(
                    state = toCycloneDxState(statement.status).token,
                    justification =
                        (statement.status as? VexStatus.NotAffected)
                            ?.let { status -> toCycloneDxJustification(status.justification).token },
                    detail = statement.detail,
                ),
            affects = statement.products.map { purl -> AffectsDto(purl.value) },
        )
}
