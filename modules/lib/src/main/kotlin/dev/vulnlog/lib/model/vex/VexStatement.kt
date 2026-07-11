// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.model.vex

import dev.vulnlog.lib.model.Disposition
import dev.vulnlog.lib.model.Purl
import dev.vulnlog.lib.model.Release
import dev.vulnlog.lib.model.Severity
import dev.vulnlog.lib.model.VulnId
import java.time.LocalDate

/**
 * One VEX statement: the exploitability assessment of one vulnerability for one target release.
 * Format-neutral intermediate representation consumed by the VEX writers.
 */
data class VexStatement(
    /**
     * Primary vulnerability identifier.
     */
    val id: VulnId,
    /**
     * Alternative identifiers, sorted for deterministic output.
     */
    val aliases: List<VulnId> = emptyList(),
    /**
     * Human-readable description of the vulnerability.
     */
    val description: String? = null,
    /**
     * Derived exploitability status for the target release.
     */
    val status: VexStatus,
    /**
     * The project's own severity assessment. Present when the verdict is affected.
     */
    val severity: Severity? = null,
    /**
     * Stated remediation intent. Present when the verdict is affected and an intent was recorded.
     */
    val disposition: Disposition? = null,
    /**
     * Free-text analysis explaining how the status was determined.
     */
    val detail: String? = null,
    /**
     * Earliest report date; the day the vulnerability became known to the project.
     */
    val published: LocalDate? = null,
    /**
     * Date the analysis was performed.
     */
    val updated: LocalDate? = null,
    /**
     * Release carrying the resolution, when one is recorded. Whether the target contains it is
     * already folded into [status]: fixed means contained, affected with a fix release means the
     * fix ships later.
     */
    val fixIn: Release? = null,
    /**
     * Note describing how the vulnerability was resolved, when the resolution carries one.
     */
    val fixNote: String? = null,
    /**
     * Product identifiers of the target release this statement applies to.
     */
    val products: List<Purl>,
    /**
     * Package URLs of the affected dependencies.
     */
    val packages: List<Purl>,
)
