// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.core

import dev.vulnlog.lib.model.VulnId

/**
 * The authority publishing a vulnerability identifier. Shared by the VEX writers: CycloneDX emits
 * it as `source.{name,url}`, OpenVEX as the vulnerability `@id` URL.
 */
fun vulnIdSourceName(id: VulnId): String =
    when (id) {
        is VulnId.Cve -> "NVD"
        is VulnId.Ghsa -> "GitHub Advisories"
        is VulnId.RustSec -> "RustSec"
        is VulnId.Snyk -> "Snyk"
    }

/** The documentation URL for a vulnerability identifier at its publishing authority. */
fun vulnIdSourceUrl(id: VulnId): String =
    when (id) {
        is VulnId.Cve -> "https://nvd.nist.gov/vuln/detail/${id.id}"
        is VulnId.Ghsa -> "https://github.com/advisories/${id.id}"
        is VulnId.RustSec -> "https://rustsec.org/advisories/${id.id}"
        is VulnId.Snyk -> "https://security.snyk.io/vuln/${id.id}"
    }
