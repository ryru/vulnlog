// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.model

/**
 * A 1-based position in a source file: the line and column a finding points at. Wrapping the two
 * coordinates keeps positions from being passed around as bare [Int] pairs and gives a single,
 * editor-friendly `line:column` rendering.
 */
data class SourceLocation(
    val line: Int,
    val column: Int,
) {
    override fun toString(): String = "$line:$column"
}
