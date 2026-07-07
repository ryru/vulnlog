// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.core

import dev.vulnlog.lib.model.Purl
import dev.vulnlog.lib.model.Release
import dev.vulnlog.lib.model.Resolution
import dev.vulnlog.lib.model.Verdict
import dev.vulnlog.lib.model.VulnerabilityEntry
import dev.vulnlog.lib.model.VulnlogFile
import dev.vulnlog.lib.model.vex.VexStatement
import dev.vulnlog.lib.model.vex.VexStatus

/**
 * Builds the VEX statements for one target release. The list order of [VulnlogFile.releases] is the
 * release timeline: a vulnerability produces a statement when its earliest affected release is not
 * newer than the target. Statements are sorted by vulnerability id for deterministic output.
 *
 * @param vulnlogFile The Vulnlog file containing release and vulnerability records.
 * @param target The release the VEX document is generated for. Must be defined in the releases section.
 */
fun buildVexStatements(
    vulnlogFile: VulnlogFile,
    target: Release,
): List<VexStatement> {
    val releaseOrder = vulnlogFile.releases.map { it.id }
    val targetIndex = releaseOrder.indexOf(target)
    require(targetIndex >= 0) { "release '${target.value}' is not defined" }
    val products = vulnlogFile.releases[targetIndex].purls.map { it.purl }
    return vulnlogFile.vulnerabilities
        .filter { entry -> concernsTarget(entry, releaseOrder, targetIndex) }
        .map { entry -> toStatement(entry, releaseOrder, targetIndex, products) }
        .sortedBy { statement -> statement.id.id }
}

private fun concernsTarget(
    entry: VulnerabilityEntry,
    releaseOrder: List<Release>,
    targetIndex: Int,
): Boolean {
    val earliestAffected =
        entry.releases
            .map(releaseOrder::indexOf)
            .filter { it >= 0 }
            .minOrNull()
    return earliestAffected != null && earliestAffected <= targetIndex
}

private fun toStatement(
    entry: VulnerabilityEntry,
    releaseOrder: List<Release>,
    targetIndex: Int,
    products: List<Purl>,
): VexStatement =
    VexStatement(
        id = entry.id,
        status = deriveStatus(entry, releaseOrder, targetIndex),
        detail = entry.analysis,
        products = products.sortedBy { it.value },
        packages = entry.packages.sortedBy { it.value },
    )

private fun deriveStatus(
    entry: VulnerabilityEntry,
    releaseOrder: List<Release>,
    targetIndex: Int,
): VexStatus =
    when (val verdict = entry.verdict) {
        is Verdict.NotAffected -> VexStatus.NotAffected(verdict.justification)
        is Verdict.Affected ->
            if (targetContainsFix(entry.resolution, releaseOrder, targetIndex)) VexStatus.Fixed else VexStatus.Affected
        is Verdict.RiskAcceptable -> VexStatus.Affected
        Verdict.UnderInvestigation -> VexStatus.UnderInvestigation
    }

private fun targetContainsFix(
    resolution: Resolution?,
    releaseOrder: List<Release>,
    targetIndex: Int,
): Boolean {
    if (resolution == null) return false
    val resolutionIndex = releaseOrder.indexOf(resolution.release)
    return resolutionIndex in 0..targetIndex
}
