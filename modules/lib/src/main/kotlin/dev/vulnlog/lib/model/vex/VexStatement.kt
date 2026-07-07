// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.model.vex

import dev.vulnlog.lib.model.Purl
import dev.vulnlog.lib.model.VulnId

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
     * Derived exploitability status for the target release.
     */
    val status: VexStatus,
    /**
     * Free-text analysis explaining how the status was determined.
     */
    val detail: String? = null,
    /**
     * Product identifiers of the target release this statement applies to.
     */
    val products: List<Purl>,
    /**
     * Package URLs of the affected dependencies.
     */
    val packages: List<Purl>,
)
