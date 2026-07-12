// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.core

import dev.vulnlog.lib.model.Disposition
import dev.vulnlog.lib.model.Project
import dev.vulnlog.lib.model.Release
import dev.vulnlog.lib.model.VexJustification
import dev.vulnlog.lib.model.VulnId
import dev.vulnlog.lib.model.vex.Rfc3339Timestamp
import dev.vulnlog.lib.model.vex.VexStatement
import dev.vulnlog.lib.model.vex.VexStatus
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import java.time.LocalDate

private fun statement(
    status: VexStatus,
    disposition: Disposition? = null,
    fixIn: Release? = null,
    fixNote: String? = null,
    detail: String? = null,
    published: LocalDate? = null,
    updated: LocalDate? = null,
) = VexStatement(
    id = VulnId.Cve("CVE-2026-0001"),
    status = status,
    disposition = disposition,
    detail = detail,
    published = published,
    updated = updated,
    fixIn = fixIn,
    fixNote = fixNote,
    products = emptyList(),
    packages = emptyList(),
)

private val notAffected = VexStatus.NotAffected(VexJustification.COMPONENT_NOT_PRESENT)

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
                toOpenVexActionStatement(statement(notAffected)).shouldBeNull()
            }
        }

        context("author derivation") {

            test("the contact is appended in parentheses when present") {
                val project =
                    Project(
                        organization = "Example Org",
                        name = "example",
                        author = "Sec Team",
                        contact = "security@example.org",
                    )

                toOpenVexAuthor(project) shouldBe "Sec Team (security@example.org)"
            }

            test("the author stands alone without a contact") {
                val project = Project(organization = "Example Org", name = "example", author = "Sec Team")

                toOpenVexAuthor(project) shouldBe "Sec Team"
            }
        }

        context("analysis text routing") {

            test("a not_affected statement routes the analysis to the impact statement") {
                val routed = statement(notAffected, detail = "Not in the execute path.")

                toOpenVexImpactStatement(routed) shouldBe "Not in the execute path."
                toOpenVexStatusNotes(routed).shouldBeNull()
            }

            test("every other status routes the analysis to the status notes") {
                val routed = statement(VexStatus.Affected, detail = "The risk is accepted.")

                toOpenVexStatusNotes(routed) shouldBe "The risk is accepted."
                toOpenVexImpactStatement(routed).shouldBeNull()
            }

            test("no analysis text routes nowhere") {
                toOpenVexImpactStatement(statement(notAffected)).shouldBeNull()
                toOpenVexStatusNotes(statement(VexStatus.Affected)).shouldBeNull()
            }
        }

        context("statement timestamp derivation") {
            val documentTimestamp = Rfc3339Timestamp.of(LocalDate.of(2026, 4, 25))

            test("the analysis date wins") {
                val dated =
                    statement(
                        VexStatus.Affected,
                        published = LocalDate.of(2026, 4, 6),
                        updated = LocalDate.of(2026, 4, 7),
                    )

                toOpenVexStatementTimestamp(dated, documentTimestamp) shouldBe
                    Rfc3339Timestamp.of(LocalDate.of(2026, 4, 7))
            }

            test("the earliest report date is the first fallback") {
                val dated = statement(VexStatus.Affected, published = LocalDate.of(2026, 4, 6))

                toOpenVexStatementTimestamp(dated, documentTimestamp) shouldBe
                    Rfc3339Timestamp.of(LocalDate.of(2026, 4, 6))
            }

            test("the document timestamp is the last resort") {
                toOpenVexStatementTimestamp(statement(VexStatus.Affected), documentTimestamp) shouldBe
                    documentTimestamp
            }
        }
    })
