// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse

import dev.vulnlog.lib.model.SourceLocation
import dev.vulnlog.lib.model.VulnlogFileRaw
import dev.vulnlog.lib.result.YamlSyntaxResult
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import org.snakeyaml.engine.v2.exceptions.Mark
import org.snakeyaml.engine.v2.exceptions.MarkedYamlEngineException
import org.snakeyaml.engine.v2.exceptions.YamlEngineException
import java.util.Optional

/**
 * Marks are required so the parser reports the line and column of a problem. Duplicate keys are
 * tolerated here: this stage only decides whether the bytes are well-formed YAML, leaving every
 * Vulnlog-specific judgement to the semantic stage.
 */
private val syntaxSettings: LoadSettings =
    LoadSettings
        .builder()
        .setUseMarks(true)
        .setAllowDuplicateKeys(true)
        .build()

/**
 * Syntactic stage: decides whether [raw] is well-formed YAML, independent of whether it is a valid
 * Vulnlog document. This is the same snakeyaml-engine that Jackson reads through, so the two never
 * disagree on well-formedness; running it explicitly lets us surface the first parser error with its
 * source location instead of a bare message.
 */
fun checkYamlSyntax(raw: VulnlogFileRaw): YamlSyntaxResult =
    try {
        Load(syntaxSettings).loadFromString(raw.content)
        YamlSyntaxResult.WellFormed
    } catch (e: MarkedYamlEngineException) {
        // The context mark points at the construct that is actually wrong (the key missing its
        // colon, the quote that was never closed); the problem mark is only where the scanner
        // finally gave up, often a line or two downstream. Report the construct, and name the
        // detection point too when it differs so block-structure errors still surface it.
        val construct = e.contextMark.toSourceLocation()
        val detected = e.problemMark.toSourceLocation()
        val problem = e.problem ?: e.message ?: "Invalid YAML."
        val message = if (detected != null && detected != construct) "$problem (detected at $detected)" else problem
        YamlSyntaxResult.Malformed(message, construct ?: detected)
    } catch (e: YamlEngineException) {
        YamlSyntaxResult.Malformed(e.message ?: "Invalid YAML.", location = null)
    }

private fun Optional<Mark>.toSourceLocation(): SourceLocation? =
    orElse(null)?.let { SourceLocation(it.line + 1, it.column + 1) }
