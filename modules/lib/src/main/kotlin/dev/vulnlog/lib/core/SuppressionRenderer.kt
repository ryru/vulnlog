// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.core

import dev.vulnlog.lib.model.suppress.SuppressionOutput

/**
 * Renders one diagnostic line for a written suppression output, stating the target, the format,
 * and the number of entries. Shared by the CLI and the Gradle plugin.
 */
fun renderSuppressionWritten(
    target: String,
    output: SuppressionOutput,
): String = "wrote $target: ${formatName(output)} format, ${pluralizeEntries(entryCount(output))}"

private fun formatName(output: SuppressionOutput): String =
    when (output) {
        is SuppressionOutput.GenericSuppression -> "generic"
        is SuppressionOutput.TrivySuppression -> "trivy"
        is SuppressionOutput.SnykSuppression -> "snyk"
        is SuppressionOutput.CargoAuditSuppression -> "cargo-audit"
    }

private fun entryCount(output: SuppressionOutput): Int =
    when (output) {
        is SuppressionOutput.GenericSuppression -> output.entries.size
        is SuppressionOutput.TrivySuppression -> output.entries.size
        is SuppressionOutput.SnykSuppression -> output.entries.size
        is SuppressionOutput.CargoAuditSuppression -> output.entries.size
    }

private fun pluralizeEntries(count: Int): String = if (count == 1) "1 entry" else "$count entries"
