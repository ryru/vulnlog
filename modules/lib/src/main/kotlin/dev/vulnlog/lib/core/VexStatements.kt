// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.core

import dev.vulnlog.lib.model.Purl
import dev.vulnlog.lib.model.PurlEntry
import dev.vulnlog.lib.model.Release
import dev.vulnlog.lib.model.ReleaseEntry
import dev.vulnlog.lib.model.Resolution
import dev.vulnlog.lib.model.Tag
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
 * @param documentTags Narrows the document to the release purls carrying one of these tags. Empty
 * means no narrowing. Statements stay in the document either way; a vulnerability whose products
 * all fall outside the scope keeps an empty product list.
 */
fun buildVexStatements(
    vulnlogFile: VulnlogFile,
    target: Release,
    documentTags: Set<Tag> = emptySet(),
): List<VexStatement> {
    val releaseOrder = vulnlogFile.releases.map { it.id }
    val targetIndex = releaseOrder.indexOf(target)
    require(targetIndex >= 0) { "release '${target.value}' is not defined" }
    val purls = scopePurlsToTags(vulnlogFile.releases[targetIndex].purls, documentTags)
    return vulnlogFile.vulnerabilities
        .filter { entry -> concernsTarget(entry, releaseOrder, targetIndex) }
        .map { entry -> toStatement(entry, releaseOrder, targetIndex, scopeProducts(purls, entry.tags)) }
        .sortedBy { statement -> statement.id.id }
}

/**
 * Builds the VEX statements for every release in [aggregateReleases], one statement per
 * vulnerability and release, each anchored to that release's purls. Statements identical across
 * releases collapse into one, so a vulnerability whose products fall outside the scope in every
 * release (see the empty-product rule) appears exactly once. Statements are sorted by
 * vulnerability id first and release timeline second.
 *
 * @param vulnlogFile The Vulnlog file containing release and vulnerability records.
 * @param aggregateReleases The releases the document covers. Every release must be defined in the
 * releases section; the caller decides the set, typically the releases that carry purls in scope.
 * @param documentTags Narrows the document to the release purls carrying one of these tags.
 */
fun buildAggregateVexStatements(
    vulnlogFile: VulnlogFile,
    aggregateReleases: List<Release>,
    documentTags: Set<Tag> = emptySet(),
): List<VexStatement> =
    aggregateReleases
        .flatMap { release -> buildVexStatements(vulnlogFile, release, documentTags) }
        .distinct()
        .sortedBy { statement -> statement.id.id }

/**
 * Narrows a release to the purls carrying one of the [documentTags]. Strict selection: purls
 * without tags are excluded from a tag-scoped document. Empty [documentTags] means no narrowing.
 */
fun scopeReleaseToTags(
    release: ReleaseEntry,
    documentTags: Set<Tag>,
): ReleaseEntry = release.copy(purls = scopePurlsToTags(release.purls, documentTags))

private fun scopePurlsToTags(
    purls: List<PurlEntry>,
    documentTags: Set<Tag>,
): List<PurlEntry> =
    if (documentTags.isEmpty()) {
        purls
    } else {
        purls.filter { entry -> entry.tags.any(documentTags::contains) }
    }

/**
 * Selects the release purls a vulnerability applies to. A shared tag between vulnerability and purl
 * is enough to include the purl; purls without tags are always included; vulnerabilities without
 * tags apply to every purl.
 */
private fun scopeProducts(
    purls: List<PurlEntry>,
    vulnerabilityTags: List<Tag>,
): List<Purl> =
    purls
        .filter { entry ->
            entry.tags.isEmpty() || vulnerabilityTags.isEmpty() || entry.tags.any(vulnerabilityTags::contains)
        }.map { entry -> entry.purl }

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
): VexStatement {
    val affected = entry.verdict as? Verdict.Affected
    return VexStatement(
        id = entry.id,
        aliases = entry.aliases.sortedBy { alias -> alias.id },
        description = entry.description,
        status = deriveStatus(entry, releaseOrder, targetIndex),
        severity = affected?.severity,
        disposition = affected?.disposition,
        detail = entry.analysis,
        published = entry.reports.mapNotNull { report -> report.at }.minOrNull(),
        updated = entry.analyzedAt,
        fixIn = entry.resolution?.release,
        fixNote = entry.resolution?.note,
        products = products.sortedBy { it.value },
        packages = entry.packages.sortedBy { it.value },
    )
}

private fun deriveStatus(
    entry: VulnerabilityEntry,
    releaseOrder: List<Release>,
    targetIndex: Int,
): VexStatus =
    when (val verdict = entry.verdict) {
        is Verdict.NotAffected -> VexStatus.NotAffected(verdict.justification)
        is Verdict.Affected ->
            if (targetContainsFix(entry.resolution, releaseOrder, targetIndex)) VexStatus.Fixed else VexStatus.Affected
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
