// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.openvex

import dev.vulnlog.lib.core.OpenVexIdentity
import dev.vulnlog.lib.core.nextOpenVexIdentity
import dev.vulnlog.lib.model.Project
import dev.vulnlog.lib.model.vex.VexStatement
import tools.jackson.core.JacksonException
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.databind.node.ObjectNode
import java.time.Instant
import java.time.OffsetDateTime
import java.time.format.DateTimeParseException

private const val CONTEXT_PREFIX = "https://openvex.dev/ns"

sealed interface OpenVexDocumentResult {
    /**
     * The baseline document already carries the same statements; the baseline stays current.
     */
    data object Unchanged : OpenVexDocumentResult

    /**
     * A document to write to the output path.
     */
    data class Document(
        val content: String,
    ) : OpenVexDocumentResult
}

private val mapper = JsonMapper.builder().build()

/**
 * Generates the OpenVEX document, continuing the identity of the [baseline] document when one is
 * given: a valid baseline keeps its `@id` and original `timestamp`, bumps the version, and records
 * [now] as `last_updated`. An absent or invalid baseline starts a new identity from [newDocumentId]
 * issued at [now]. When the document equals the baseline apart from `version`, `timestamp`, and
 * `last_updated`, the result is [OpenVexDocumentResult.Unchanged] and the baseline stays current.
 */
fun generateOpenVexDocument(
    project: Project,
    statements: List<VexStatement>,
    baseline: String?,
    newDocumentId: () -> String,
    now: Instant,
    toolVersion: String,
): OpenVexDocumentResult {
    val existing = baseline?.let(::parseDocument)
    val identity = nextOpenVexIdentity(existing?.let(::priorIdentity), newDocumentId, now)
    val document =
        OpenVexMapper.toDto(
            project = project,
            statements = statements,
            documentId = identity.id,
            version = identity.version,
            timestamp = identity.timestamp,
            lastUpdated = identity.lastUpdated,
            toolVersion = toolVersion,
        )
    val content = OpenVexWriter.write(document)
    if (existing != null && comparableTree(parseDocument(content)!!) == comparableTree(existing)) {
        return OpenVexDocumentResult.Unchanged
    }
    return OpenVexDocumentResult.Document(content)
}

private fun parseDocument(content: String): ObjectNode? =
    try {
        mapper.readTree(content) as? ObjectNode
    } catch (_: JacksonException) {
        null
    }

private fun priorIdentity(document: ObjectNode): OpenVexIdentity? {
    val context = document.path("@context").asString(null) ?: return null
    if (!context.startsWith(CONTEXT_PREFIX)) return null
    val id = document.path("@id").asString(null) ?: return null
    val timestamp = document.path("timestamp").asString(null)?.let(::parseTimestamp) ?: return null
    return OpenVexIdentity(id, document.path("version").asInt(1), timestamp, lastUpdated = null)
}

private fun parseTimestamp(value: String): Instant? =
    try {
        OffsetDateTime.parse(value).toInstant()
    } catch (_: DateTimeParseException) {
        null
    }

private fun comparableTree(document: ObjectNode): JsonNode {
    val copy = document.deepCopy()
    copy.remove("version")
    copy.remove("timestamp")
    copy.remove("last_updated")
    return copy
}
