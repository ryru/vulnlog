// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.core

import dev.vulnlog.lib.model.Disposition
import dev.vulnlog.lib.model.Release
import dev.vulnlog.lib.model.VexJustification
import dev.vulnlog.lib.model.VulnId
import dev.vulnlog.lib.model.vex.VexStatement
import dev.vulnlog.lib.model.vex.VexStatus
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe

private fun statement(
    status: VexStatus,
    disposition: Disposition? = null,
    fixIn: Release? = null,
    fixNote: String? = null,
) = VexStatement(
    id = VulnId.Cve("CVE-2026-0001"),
    status = status,
    disposition = disposition,
    fixIn = fixIn,
    fixNote = fixNote,
    products = emptyList(),
    packages = emptyList(),
)

class OpenVexVocabularyTest :
    FunSpec({
        test("every status maps onto its OpenVEX status") {
            toOpenVexStatus(VexStatus.NotAffected(VexJustification.COMPONENT_NOT_PRESENT)) shouldBe
                OpenVexStatus.NOT_AFFECTED
            toOpenVexStatus(VexStatus.Affected) shouldBe OpenVexStatus.AFFECTED
            toOpenVexStatus(VexStatus.Fixed) shouldBe OpenVexStatus.FIXED
            toOpenVexStatus(VexStatus.UnderInvestigation) shouldBe OpenVexStatus.UNDER_INVESTIGATION
        }

        test("every justification maps onto its OpenVEX justification") {
            VexJustification.entries.forEach { justification ->
                toOpenVexJustification(justification).token shouldBe
                    justification.name.lowercase()
            }
        }

        test("the OpenVEX tokens match the 0.2.0 schema enums") {
            OpenVexStatus.entries.map { it.token } shouldBe
                listOf("not_affected", "affected", "fixed", "under_investigation")
            OpenVexJustification.entries.map { it.token } shouldBe
                listOf(
                    "component_not_present",
                    "vulnerable_code_not_present",
                    "vulnerable_code_not_in_execute_path",
                    "vulnerable_code_cannot_be_controlled_by_adversary",
                    "inline_mitigations_already_exist",
                )
        }

        context("action statement derivation") {
            val fix = Release("2.0.0")

            test("no disposition with a later fix release asks to update") {
                toOpenVexActionStatement(statement(VexStatus.Affected, fixIn = fix)) shouldBe
                    "Update to release 2.0.0."
            }

            test("no disposition and no fix release states that no remediation exists") {
                toOpenVexActionStatement(statement(VexStatus.Affected)) shouldBe
                    "No remediation is available yet."
            }

            test("will-fix with a later fix release asks to update") {
                toOpenVexActionStatement(statement(VexStatus.Affected, Disposition.WILL_FIX, fix)) shouldBe
                    "Update to release 2.0.0."
            }

            test("will-fix without a fix release announces the planned fix") {
                toOpenVexActionStatement(statement(VexStatus.Affected, Disposition.WILL_FIX)) shouldBe
                    "A fix is planned but not yet available."
            }

            test("wont-fix with a later fix release states the accepted risk and the fix release") {
                toOpenVexActionStatement(statement(VexStatus.Affected, Disposition.WONT_FIX, fix)) shouldBe
                    "The risk is accepted for this release. A fix ships with release 2.0.0."
            }

            test("wont-fix without a fix release states the accepted risk") {
                toOpenVexActionStatement(statement(VexStatus.Affected, Disposition.WONT_FIX)) shouldBe
                    "The risk is accepted. No fix is planned."
            }

            test("the resolution note is appended to the update action") {
                toOpenVexActionStatement(
                    statement(VexStatus.Affected, fixIn = fix, fixNote = "Bumped logback to 1.5.20."),
                ) shouldBe "Update to release 2.0.0. Bumped logback to 1.5.20."
            }

            test("statuses other than affected carry no action statement") {
                toOpenVexActionStatement(statement(VexStatus.Fixed, fixIn = fix)).shouldBeNull()
                toOpenVexActionStatement(statement(VexStatus.UnderInvestigation)).shouldBeNull()
                toOpenVexActionStatement(
                    statement(VexStatus.NotAffected(VexJustification.COMPONENT_NOT_PRESENT)),
                ).shouldBeNull()
            }
        }
    })
