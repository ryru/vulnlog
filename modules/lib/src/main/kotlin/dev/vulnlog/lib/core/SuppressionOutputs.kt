// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.core

import dev.vulnlog.lib.model.ReporterType
import dev.vulnlog.lib.model.suppress.SuppressedVulnerability
import dev.vulnlog.lib.model.suppress.SuppressionFormat
import dev.vulnlog.lib.model.suppress.SuppressionOutput
import dev.vulnlog.lib.model.suppress.SuppressionVuln
import dev.vulnlog.lib.result.SuppressionExclusion
import dev.vulnlog.lib.result.SuppressionOutputsResult
import dev.vulnlog.lib.shell.SuppressionFormatRequest

/**
 * Builds the per-reporter suppression outputs for the given target reporters, applying the requested
 * output format. Every entry that does not make it into an output is returned as an exclusion:
 * entries whose vulnerability id type the format does not support, and entries of reporters without
 * a suppressible format (such as [ReporterType.OTHER]).
 *
 * @param targetReporters The reporters to generate suppression outputs for.
 * @param reporterToSuppressions The suppressed vulnerabilities grouped by reporter.
 * @param formatRequest The requested output format. Defaults to [SuppressionFormatRequest.Auto].
 * @return The [SuppressionOutput] objects, one per suppressible target reporter, plus all exclusions.
 */
fun buildSuppressionOutputs(
    targetReporters: Set<ReporterType>,
    reporterToSuppressions: Map<ReporterType, List<SuppressedVulnerability>>,
    formatRequest: SuppressionFormatRequest = SuppressionFormatRequest.Auto,
): SuppressionOutputsResult {
    val (suppressible, unsuppressible) = targetReporters.partition { reporter -> reporter != ReporterType.OTHER }
    val outputs =
        suppressible
            .map { reporter -> reporter to resolveFormatRequest(formatRequest, reporter) }
            .map { (reporter, format) -> createSuppression(format, reporterToSuppressions[reporter]) }
    val reporterExclusions = unsupportedReporterExclusions(unsuppressible, reporterToSuppressions)
    return SuppressionOutputsResult(
        outputs = outputs.map(OutputWithExclusions::output).toSet(),
        exclusions = (outputs.flatMap(OutputWithExclusions::exclusions) + reporterExclusions).distinct(),
    )
}

private data class OutputWithExclusions(
    val output: SuppressionOutput,
    val exclusions: List<SuppressionExclusion>,
)

private fun unsupportedReporterExclusions(
    reporters: List<ReporterType>,
    reporterToSuppressions: Map<ReporterType, List<SuppressedVulnerability>>,
): List<SuppressionExclusion> =
    reporters.flatMap { reporter ->
        reporterToSuppressions[reporter].orEmpty().map { suppression ->
            SuppressionExclusion.UnsupportedReporter(suppression.id, reporter)
        }
    }

private fun unsupportedIdExclusions(
    unsupported: List<SuppressedVulnerability>,
    fileName: String,
    format: SuppressionFormat,
): List<SuppressionExclusion> =
    unsupported.map { suppression -> SuppressionExclusion.UnsupportedIdType(suppression.id, fileName, format) }

private fun resolveFormatRequest(
    format: SuppressionFormatRequest,
    reporter: ReporterType,
): SuppressionFormat =
    when (format) {
        SuppressionFormatRequest.Auto -> nativeFormat(reporter) ?: SuppressionFormat.GenericFormat.Generic(reporter)
        SuppressionFormatRequest.Generic -> SuppressionFormat.GenericFormat.Generic(reporter)
    }

private fun nativeFormat(reporter: ReporterType): SuppressionFormat.NativeFormat? =
    when (reporter) {
        ReporterType.CARGO_AUDIT -> SuppressionFormat.NativeFormat.CargoAudit
        ReporterType.SNYK -> SuppressionFormat.NativeFormat.Snyk
        ReporterType.TRIVY -> SuppressionFormat.NativeFormat.Trivy
        else -> null
    }

private fun createSuppression(
    format: SuppressionFormat,
    suppressions: List<SuppressedVulnerability>?,
): OutputWithExclusions {
    val suppressionEntries = suppressions ?: emptyList()
    return when (format) {
        is SuppressionFormat.GenericFormat.Generic -> createGenericSuppression(format, suppressionEntries)
        is SuppressionFormat.NativeFormat.Trivy -> createTrivySuppression(format, suppressionEntries)
        is SuppressionFormat.NativeFormat.Snyk -> createSnykSuppression(format, suppressionEntries)
        is SuppressionFormat.NativeFormat.CargoAudit -> createCargoAuditSuppression(format, suppressionEntries)
    }
}

private fun createGenericSuppression(
    format: SuppressionFormat.GenericFormat.Generic,
    suppressions: List<SuppressedVulnerability>,
): OutputWithExclusions {
    val (supported, unsupported) = suppressions.partition { it.id::class in format.vulnIdTypes }
    val entries =
        supported
            .map { suppression ->
                SuppressionVuln.GenericSuppressionEntry(
                    id = suppression.id,
                    expiresAt = suppression.expiresAt,
                    reason = suppression.analysis,
                )
            }.toSet()
    val output =
        SuppressionOutput.GenericSuppression(
            fileName = format.reporter.name.lowercase() + ".generic.json",
            entries = entries,
        )
    return OutputWithExclusions(output, unsupportedIdExclusions(unsupported, output.fileName, format))
}

private fun createTrivySuppression(
    format: SuppressionFormat.NativeFormat.Trivy,
    suppressions: List<SuppressedVulnerability>,
): OutputWithExclusions {
    val (supported, unsupported) = suppressions.partition { it.id::class in format.vulnIdTypes }
    val entries =
        supported
            .map { suppression ->
                SuppressionVuln.TrivySuppressionEntry(
                    id = suppression.id,
                    expiresAt = suppression.expiresAt,
                    reason = suppression.analysis,
                )
            }.toSet()
    val output = SuppressionOutput.TrivySuppression(entries = entries)
    return OutputWithExclusions(output, unsupportedIdExclusions(unsupported, output.fileName, format))
}

private fun createCargoAuditSuppression(
    format: SuppressionFormat.NativeFormat.CargoAudit,
    suppressions: List<SuppressedVulnerability>,
): OutputWithExclusions {
    val (supported, unsupported) = suppressions.partition { it.id::class in format.vulnIdTypes }
    val entries =
        supported
            .map { suppression -> SuppressionVuln.CargoAuditSuppressionEntry(id = suppression.id) }
            .toSet()
    val output = SuppressionOutput.CargoAuditSuppression(entries = entries)
    return OutputWithExclusions(output, unsupportedIdExclusions(unsupported, output.fileName, format))
}

private fun createSnykSuppression(
    format: SuppressionFormat.NativeFormat.Snyk,
    suppressions: List<SuppressedVulnerability>,
): OutputWithExclusions {
    val (supported, unsupported) = suppressions.partition { it.id::class in format.vulnIdTypes }
    val entries =
        supported
            .map { suppression ->
                SuppressionVuln.SnykSuppressionEntry(
                    id = suppression.id,
                    expiresAt = suppression.expiresAt,
                    reason = suppression.analysis,
                )
            }.toSet()
    val output = SuppressionOutput.SnykSuppression(entries = entries)
    return OutputWithExclusions(output, unsupportedIdExclusions(unsupported, output.fileName, format))
}
