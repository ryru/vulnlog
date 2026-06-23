// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse

import dev.vulnlog.lib.model.SourceLocation
import org.snakeyaml.engine.v2.api.LoadSettings
import org.snakeyaml.engine.v2.composer.Composer
import org.snakeyaml.engine.v2.nodes.MappingNode
import org.snakeyaml.engine.v2.nodes.Node
import org.snakeyaml.engine.v2.nodes.ScalarNode
import org.snakeyaml.engine.v2.nodes.SequenceNode
import org.snakeyaml.engine.v2.parser.ParserImpl
import org.snakeyaml.engine.v2.scanner.StreamReader
import tools.jackson.core.JacksonException

/**
 * Source positions of a parsed YAML document, looked up by the logical path of a value. Jackson's
 * streaming parser reports a binding failure wherever it stopped reading (often the next sibling or
 * end of file), not at the value the error is about. Composing a marks-aware node tree lets us
 * resolve the path Jackson hands us (e.g. `vulnerabilities[0]`) back to the line it really sits on.
 */
internal class YamlSourceMap private constructor(
    private val root: Node?,
) {
    /**
     * The position of the deepest node along [path] that exists in the document. A path that ends at
     * a missing field (the field is absent, which is why binding failed) resolves to the node that
     * should contain it, i.e. the offending entry rather than its absent child.
     */
    fun locate(path: List<JacksonException.Reference>): SourceLocation? {
        var node = root ?: return null
        for (reference in path) {
            node = step(node, reference) ?: break
        }
        return node.startMark.orElse(null)?.let { SourceLocation(it.line + 1, it.column + 1) }
    }

    private fun step(
        node: Node,
        reference: JacksonException.Reference,
    ): Node? =
        when {
            reference.index >= 0 -> (node as? SequenceNode)?.value?.getOrNull(reference.index)
            reference.propertyName != null ->
                (node as? MappingNode)
                    ?.value
                    ?.firstOrNull { (it.keyNode as? ScalarNode)?.value == reference.propertyName }
                    ?.valueNode
            else -> null
        }

    companion object {
        private val settings: LoadSettings =
            LoadSettings
                .builder()
                .setUseMarks(true)
                .setAllowDuplicateKeys(true)
                .build()

        fun of(content: String): YamlSourceMap =
            YamlSourceMap(
                runCatching {
                    Composer(settings, ParserImpl(settings, StreamReader(settings, content))).singleNode.orElse(null)
                }.getOrNull(),
            )
    }
}
