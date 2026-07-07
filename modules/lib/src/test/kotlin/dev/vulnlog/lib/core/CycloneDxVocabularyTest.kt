// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.core

import dev.vulnlog.lib.model.VexJustification
import dev.vulnlog.lib.model.vex.VexStatus
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class CycloneDxVocabularyTest :
    FunSpec({
        test("every status maps onto its CycloneDX state") {
            toCycloneDxState(VexStatus.NotAffected(VexJustification.COMPONENT_NOT_PRESENT)) shouldBe
                CycloneDxState.NOT_AFFECTED
            toCycloneDxState(VexStatus.Affected) shouldBe CycloneDxState.EXPLOITABLE
            toCycloneDxState(VexStatus.Fixed) shouldBe CycloneDxState.RESOLVED
            toCycloneDxState(VexStatus.UnderInvestigation) shouldBe CycloneDxState.IN_TRIAGE
        }

        test("every justification maps onto its CycloneDX justification") {
            toCycloneDxJustification(VexJustification.COMPONENT_NOT_PRESENT) shouldBe
                CycloneDxJustification.CODE_NOT_PRESENT
            toCycloneDxJustification(VexJustification.VULNERABLE_CODE_NOT_PRESENT) shouldBe
                CycloneDxJustification.CODE_NOT_PRESENT
            toCycloneDxJustification(VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH) shouldBe
                CycloneDxJustification.CODE_NOT_REACHABLE
            toCycloneDxJustification(VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY) shouldBe
                CycloneDxJustification.PROTECTED_BY_MITIGATING_CONTROL
            toCycloneDxJustification(VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST) shouldBe
                CycloneDxJustification.PROTECTED_BY_MITIGATING_CONTROL
        }

        test("the CycloneDX tokens match the 1.7 schema enums") {
            CycloneDxState.entries.map { it.token } shouldBe
                listOf("not_affected", "exploitable", "resolved", "in_triage")
            CycloneDxJustification.entries.map { it.token } shouldBe
                listOf("code_not_present", "code_not_reachable", "protected_by_mitigating_control")
        }
    })
