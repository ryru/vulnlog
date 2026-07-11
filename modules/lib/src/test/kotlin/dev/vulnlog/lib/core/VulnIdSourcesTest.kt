// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.core

import dev.vulnlog.lib.model.VulnId
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class VulnIdSourcesTest :
    FunSpec({
        test("every id type maps onto its publishing authority") {
            vulnIdSourceName(VulnId.Cve("CVE-2026-0001")) shouldBe "NVD"
            vulnIdSourceName(VulnId.Ghsa("GHSA-aaaa-bbbb-cccc")) shouldBe "GitHub Advisories"
            vulnIdSourceName(VulnId.RustSec("RUSTSEC-2026-0001")) shouldBe "RustSec"
            vulnIdSourceName(VulnId.Snyk("SNYK-JS-LIB-123")) shouldBe "Snyk"
        }

        test("every id type maps onto its documentation url") {
            vulnIdSourceUrl(VulnId.Cve("CVE-2026-0001")) shouldBe
                "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
            vulnIdSourceUrl(VulnId.Ghsa("GHSA-aaaa-bbbb-cccc")) shouldBe
                "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"
            vulnIdSourceUrl(VulnId.RustSec("RUSTSEC-2026-0001")) shouldBe
                "https://rustsec.org/advisories/RUSTSEC-2026-0001"
            vulnIdSourceUrl(VulnId.Snyk("SNYK-JS-LIB-123")) shouldBe
                "https://security.snyk.io/vuln/SNYK-JS-LIB-123"
        }
    })
