// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.core

import dev.vulnlog.lib.model.Disposition
import dev.vulnlog.lib.model.Project
import dev.vulnlog.lib.model.VexJustification
import dev.vulnlog.lib.model.vex.Rfc3339Timestamp
import dev.vulnlog.lib.model.vex.VexStatement
import dev.vulnlog.lib.model.vex.VexStatus

/**
 * The OpenVEX `status` vocabulary (status labels in the 0.2.0 schema).
 */
enum class OpenVexStatus(
    val token: String,
) {
    NOT_AFFECTED("not_affected"),
    AFFECTED("affected"),
    FIXED("fixed"),
    UNDER_INVESTIGATION("under_investigation"),
}

/**
 * The OpenVEX `justification` vocabulary. The Vulnlog justifications align 1:1; only the spelling
 * changes to the snake_case labels of the spec.
 */
enum class OpenVexJustification(
    val token: String,
) {
    COMPONENT_NOT_PRESENT("component_not_present"),
    VULNERABLE_CODE_NOT_PRESENT("vulnerable_code_not_present"),
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH("vulnerable_code_not_in_execute_path"),
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY("vulnerable_code_cannot_be_controlled_by_adversary"),
    INLINE_MITIGATIONS_ALREADY_EXIST("inline_mitigations_already_exist"),
}

fun toOpenVexStatus(status: VexStatus): OpenVexStatus =
    when (status) {
        is VexStatus.NotAffected -> OpenVexStatus.NOT_AFFECTED
        VexStatus.Affected -> OpenVexStatus.AFFECTED
        VexStatus.Fixed -> OpenVexStatus.FIXED
        VexStatus.UnderInvestigation -> OpenVexStatus.UNDER_INVESTIGATION
    }

fun toOpenVexJustification(justification: VexJustification): OpenVexJustification =
    when (justification) {
        VexJustification.COMPONENT_NOT_PRESENT -> OpenVexJustification.COMPONENT_NOT_PRESENT
        VexJustification.VULNERABLE_CODE_NOT_PRESENT -> OpenVexJustification.VULNERABLE_CODE_NOT_PRESENT
        VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH ->
            OpenVexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
        VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY ->
            OpenVexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY
        VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST -> OpenVexJustification.INLINE_MITIGATIONS_ALREADY_EXIST
    }

/**
 * What the consumer should do about an affected vulnerability. OpenVEX requires an action statement
 * on every `affected` statement. The Vulnlog analysis text is a rationale, not an action, so the
 * action derives from the disposition and the fix release; the resolution note is appended when a
 * fix release is on file. Null for every other status, where the spec forbids the field.
 */
fun toOpenVexActionStatement(statement: VexStatement): String? {
    if (statement.status != VexStatus.Affected) return null
    val fixIn = statement.fixIn
    return when (statement.disposition) {
        Disposition.WONT_FIX ->
            if (fixIn != null) {
                "The risk is accepted for this release. A fix ships with release ${fixIn.value}."
            } else {
                "The risk is accepted. No fix is planned."
            }

        Disposition.WILL_FIX ->
            if (fixIn != null) updateAction(statement) else "A fix is planned but not yet available."

        null -> if (fixIn != null) updateAction(statement) else "No remediation is available yet."
    }
}

private fun updateAction(statement: VexStatement): String {
    val action = "Update to release ${statement.fixIn?.value}."
    val note = statement.fixNote
    return if (note != null) "$action $note" else action
}

/**
 * The document author: the project author, with the contact in parentheses when one is recorded.
 */
fun toOpenVexAuthor(project: Project): String =
    project.contact?.let { contact -> "${project.author} ($contact)" } ?: project.author

/**
 * The analysis text is routed to exactly one field per statement. For `not_affected` it becomes
 * the `impact_statement`, the spec field for why the product is not affected.
 */
fun toOpenVexImpactStatement(statement: VexStatement): String? =
    statement.detail.takeIf { statement.status is VexStatus.NotAffected }

/**
 * The analysis text is routed to exactly one field per statement. For every status except
 * `not_affected` it becomes the `status_notes`, the spec field for how the status was determined.
 */
fun toOpenVexStatusNotes(statement: VexStatement): String? =
    statement.detail.takeIf { statement.status !is VexStatus.NotAffected }

/**
 * The time the statement was known to be true: the analysis date, the earliest report date, or
 * the document timestamp as the last resort. The document timestamp is preserved across
 * regenerations, so the fallback never reintroduces the clock.
 */
fun toOpenVexStatementTimestamp(
    statement: VexStatement,
    documentTimestamp: Rfc3339Timestamp,
): Rfc3339Timestamp =
    statement.updated?.let(Rfc3339Timestamp::of)
        ?: statement.published?.let(Rfc3339Timestamp::of)
        ?: documentTimestamp
