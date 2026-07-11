// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.model.vex

import dev.vulnlog.lib.model.VexJustification

/**
 * Format-neutral exploitability status of a vulnerability for one target release. Derived from the
 * verdict and the resolution; VEX writers translate it into their format-specific vocabulary.
 */
sealed interface VexStatus {
    /**
     * No verdict exists yet.
     */
    data object UnderInvestigation : VexStatus

    /**
     * The target release is affected and no contained release resolves the vulnerability.
     */
    data object Affected : VexStatus

    /**
     * The target release contains the resolution.
     */
    data object Fixed : VexStatus

    /**
     * The vulnerability does not affect the target release.
     */
    data class NotAffected(
        /**
         * Justification for the verdict.
         */
        val justification: VexJustification,
    ) : VexStatus
}
