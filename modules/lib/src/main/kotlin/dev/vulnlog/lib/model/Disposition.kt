// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.model

/**
 * The stated intent of the project for an affected vulnerability. Optional with no default:
 * absence means the intent has not been stated and is never interpreted as either value.
 */
enum class Disposition {
    /**
     * The project intends to remediate the vulnerability.
     */
    WILL_FIX,

    /**
     * The project accepts the risk; no remediation is intended.
     */
    WONT_FIX,
}
