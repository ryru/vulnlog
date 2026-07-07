// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.core

import dev.vulnlog.lib.model.VexJustification
import dev.vulnlog.lib.model.vex.VexStatus

/**
 * The CycloneDX `analysis.state` vocabulary (impactAnalysisState in the 1.7 schema).
 */
enum class CycloneDxState(
    val token: String,
) {
    NOT_AFFECTED("not_affected"),
    EXPLOITABLE("exploitable"),
    RESOLVED("resolved"),
    IN_TRIAGE("in_triage"),
}

/**
 * The CycloneDX `analysis.justification` vocabulary (impactAnalysisJustification in the 1.7 schema).
 * Only the values reachable from the Vulnlog justifications are listed.
 */
enum class CycloneDxJustification(
    val token: String,
) {
    CODE_NOT_PRESENT("code_not_present"),
    CODE_NOT_REACHABLE("code_not_reachable"),
    PROTECTED_BY_MITIGATING_CONTROL("protected_by_mitigating_control"),
}

fun toCycloneDxState(status: VexStatus): CycloneDxState =
    when (status) {
        is VexStatus.NotAffected -> CycloneDxState.NOT_AFFECTED
        VexStatus.Affected -> CycloneDxState.EXPLOITABLE
        VexStatus.Fixed -> CycloneDxState.RESOLVED
        VexStatus.UnderInvestigation -> CycloneDxState.IN_TRIAGE
    }

/**
 * Lossy by design: CycloneDX merges component and code absence into `code_not_present`, and has no
 * direct equivalent for adversary-controlled reachability, which lands on
 * `protected_by_mitigating_control`.
 */
fun toCycloneDxJustification(justification: VexJustification): CycloneDxJustification =
    when (justification) {
        VexJustification.COMPONENT_NOT_PRESENT -> CycloneDxJustification.CODE_NOT_PRESENT
        VexJustification.VULNERABLE_CODE_NOT_PRESENT -> CycloneDxJustification.CODE_NOT_PRESENT
        VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH -> CycloneDxJustification.CODE_NOT_REACHABLE
        VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY ->
            CycloneDxJustification.PROTECTED_BY_MITIGATING_CONTROL
        VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST -> CycloneDxJustification.PROTECTED_BY_MITIGATING_CONTROL
    }
