// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse

import dev.vulnlog.lib.model.ParseValidationVersion
import dev.vulnlog.lib.model.SchemaVersion
import dev.vulnlog.lib.model.SourceLocation
import dev.vulnlog.lib.model.VulnlogFileRaw
import dev.vulnlog.lib.parse.v1.V1Mapper
import dev.vulnlog.lib.parse.v1.dto.VulnlogFileV1Dto
import dev.vulnlog.lib.result.ParseResult
import dev.vulnlog.lib.result.YamlSyntaxResult
import tools.jackson.core.TokenStreamLocation
import tools.jackson.databind.DatabindException
import tools.jackson.databind.ObjectMapper
import tools.jackson.databind.exc.UnrecognizedPropertyException
import tools.jackson.module.kotlin.KotlinInvalidNullException
import tools.jackson.module.kotlin.readValue

class YamlParser(
    private val mapper: ObjectMapper,
) {
    fun parse(yaml: VulnlogFileRaw): ParseResult {
        // Syntactic stage: is this well-formed YAML at all?
        when (val syntax = checkYamlSyntax(yaml)) {
            is YamlSyntaxResult.Malformed -> return ParseResult.Error(syntax.message, syntax.location)
            YamlSyntaxResult.WellFormed -> Unit
        }

        // Semantic stage: is this well-formed YAML a valid Vulnlog document?
        val schemaVersion: SchemaVersion =
            detectVersion(yaml)
                ?: return ParseResult.Error("Missing or invalid schemaVersion")

        val parseAndValidationVersion =
            when (schemaVersion.major) {
                1 -> ParseValidationVersion.V1
                else -> return ParseResult.Error(
                    "Unsupported schema version '$schemaVersion'. Try updating vulnlog.",
                )
            }

        return when (parseAndValidationVersion) {
            ParseValidationVersion.V1 -> parseV1(yaml, ParseValidationVersion.V1, schemaVersion)
        }
    }

    private fun detectVersion(yaml: VulnlogFileRaw): SchemaVersion? {
        val tree = mapper.readTree(yaml.content)
        val raw = tree.get("schemaVersion")?.stringValue() ?: return null
        return parseSchemaVersion(raw)
    }

    private fun parseV1(
        yaml: VulnlogFileRaw,
        validationVersion: ParseValidationVersion,
        schemaVersion: SchemaVersion,
    ): ParseResult {
        val dto: VulnlogFileV1Dto =
            try {
                mapper.readValue<VulnlogFileV1Dto>(yaml.content)
            } catch (e: UnrecognizedPropertyException) {
                return ParseResult.Error(unknownFieldMessage(e), e.location.toSourceLocation())
            } catch (e: KotlinInvalidNullException) {
                val location = YamlSourceMap.of(yaml.content).locate(e.path) ?: e.location.toSourceLocation()
                return ParseResult.Error("Missing required field '${e.kotlinPropertyName}'.", location)
            } catch (e: DatabindException) {
                return ParseResult.Error("YAML parse error: ${e.originalMessage}", e.location.toSourceLocation())
            }
        return V1Mapper.toDomain(validationVersion, schemaVersion, dto, yaml)
    }
}

private fun unknownFieldMessage(e: UnrecognizedPropertyException): String {
    val known = e.knownPropertyIds?.joinToString { "'$it'" }.orEmpty()
    val hint = if (known.isNotEmpty()) " Known fields: $known." else ""
    return "Unknown field '${e.propertyName}'.$hint"
}

private fun TokenStreamLocation?.toSourceLocation(): SourceLocation? =
    this?.takeIf { it.lineNr >= 1 }?.let { SourceLocation(it.lineNr, it.columnNr) }
