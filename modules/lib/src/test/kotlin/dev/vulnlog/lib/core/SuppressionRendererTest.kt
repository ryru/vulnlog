// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.core

import dev.vulnlog.lib.model.VulnId
import dev.vulnlog.lib.model.suppress.SuppressionOutput
import dev.vulnlog.lib.model.suppress.SuppressionVuln
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class SuppressionRendererTest :
    FunSpec({

        context("renderSuppressionWritten") {

            test("renders a trivy output with a single entry") {
                val output =
                    SuppressionOutput.TrivySuppression(
                        entries =
                            setOf(
                                SuppressionVuln.TrivySuppressionEntry(
                                    id = VulnId.Cve("CVE-2026-1234"),
                                    reason = "not reachable",
                                ),
                            ),
                    )

                renderSuppressionWritten("/out/.trivyignore.yaml", output) shouldBe
                    "wrote /out/.trivyignore.yaml: trivy format, 1 entry"
            }

            test("pluralizes the entry count") {
                val output =
                    SuppressionOutput.GenericSuppression(
                        entries =
                            setOf(
                                SuppressionVuln.GenericSuppressionEntry(
                                    id = VulnId.Cve("CVE-2026-1234"),
                                    reason = "not reachable",
                                ),
                                SuppressionVuln.GenericSuppressionEntry(
                                    id = VulnId.Ghsa("GHSA-aaaa-bbbb-cccc"),
                                    reason = "not reachable",
                                ),
                            ),
                    )

                renderSuppressionWritten("trivy.generic.json", output) shouldBe
                    "wrote trivy.generic.json: generic format, 2 entries"
            }

            test("renders an empty snyk output") {
                val output = SuppressionOutput.SnykSuppression(entries = emptySet())

                renderSuppressionWritten("<stdout>", output) shouldBe "wrote <stdout>: snyk format, 0 entries"
            }

            test("renders the cargo-audit format name") {
                val entry = SuppressionVuln.CargoAuditSuppressionEntry(id = VulnId.RustSec("RUSTSEC-2026-0001"))
                val output = SuppressionOutput.CargoAuditSuppression(entries = setOf(entry))

                renderSuppressionWritten("audit.toml", output) shouldBe
                    "wrote audit.toml: cargo-audit format, 1 entry"
            }
        }
    })
