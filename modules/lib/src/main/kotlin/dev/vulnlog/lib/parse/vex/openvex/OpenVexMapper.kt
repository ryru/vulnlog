// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.openvex

import dev.vulnlog.lib.core.toOpenVexActionStatement
import dev.vulnlog.lib.core.toOpenVexAuthor
import dev.vulnlog.lib.core.toOpenVexImpactStatement
import dev.vulnlog.lib.core.toOpenVexJustification
import dev.vulnlog.lib.core.toOpenVexStatementTimestamp
import dev.vulnlog.lib.core.toOpenVexStatus
import dev.vulnlog.lib.core.toOpenVexStatusNotes
import dev.vulnlog.lib.core.vulnIdSourceUrl
import dev.vulnlog.lib.model.Project
import dev.vulnlog.lib.model.Purl
import dev.vulnlog.lib.model.vex.Rfc3339Timestamp
import dev.vulnlog.lib.model.vex.VexStatement
import dev.vulnlog.lib.model.vex.VexStatus
import dev.vulnlog.lib.parse.vex.openvex.dto.DocumentDto
import dev.vulnlog.lib.parse.vex.openvex.dto.IdentifiersDto
import dev.vulnlog.lib.parse.vex.openvex.dto.ProductDto
import dev.vulnlog.lib.parse.vex.openvex.dto.StatementDto
import dev.vulnlog.lib.parse.vex.openvex.dto.SubcomponentDto
import dev.vulnlog.lib.parse.vex.openvex.dto.VulnerabilityDto
import java.time.Instant

private const val CONTEXT = "https://openvex.dev/ns/v0.2.0"
private const val ROLE = "Document Creator"

object OpenVexMapper {
    /**
     * Assembles an OpenVEX document. Document identity ([documentId], [version], [timestamp], and
     * [lastUpdated]) is decided by the caller; [toolVersion] is the version of the generating CLI.
     * Statement timestamps derive from the YAML dates and fall back to the document [timestamp],
     * which is stable across regenerations.
     */
    fun toDto(
        project: Project,
        statements: List<VexStatement>,
        documentId: String,
        version: Int,
        timestamp: Instant,
        lastUpdated: Instant?,
        toolVersion: String,
    ): DocumentDto {
        val documentTimestamp = Rfc3339Timestamp.of(timestamp)
        return DocumentDto(
            context = CONTEXT,
            id = documentId,
            author = toOpenVexAuthor(project),
            role = ROLE,
            timestamp = documentTimestamp,
            lastUpdated = lastUpdated?.let(Rfc3339Timestamp::of),
            version = version,
            tooling = "vulnlog/$toolVersion",
            statements = statements.map { statement -> toStatement(statement, project, documentTimestamp) },
        )
    }

    private fun toStatement(
        statement: VexStatement,
        project: Project,
        documentTimestamp: Rfc3339Timestamp,
    ): StatementDto {
        val timestamp = toOpenVexStatementTimestamp(statement, documentTimestamp)
        val actionStatement = toOpenVexActionStatement(statement)
        return StatementDto(
            vulnerability = toVulnerability(statement),
            timestamp = timestamp,
            products = statement.products.map { purl -> toProduct(purl, statement.packages) },
            status = toOpenVexStatus(statement.status).token,
            justification =
                (statement.status as? VexStatus.NotAffected)
                    ?.let { status -> toOpenVexJustification(status.justification).token },
            impactStatement = toOpenVexImpactStatement(statement),
            actionStatement = actionStatement,
            actionStatementTimestamp = timestamp.takeIf { actionStatement != null },
            statusNotes = toOpenVexStatusNotes(statement),
            supplier = project.organization,
        )
    }

    private fun toVulnerability(statement: VexStatement): VulnerabilityDto =
        VulnerabilityDto(
            id = vulnIdSourceUrl(statement.id),
            name = statement.id.id,
            description = statement.description,
            aliases = statement.aliases.map { alias -> alias.id },
        )

    private fun toProduct(
        purl: Purl,
        packages: List<Purl>,
    ): ProductDto =
        ProductDto(
            id = purl.value,
            identifiers = IdentifiersDto(purl = purl.value),
            subcomponents = packages.map { pkg -> SubcomponentDto(id = pkg.value) },
        )
}
