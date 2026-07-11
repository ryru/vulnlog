// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.openvex

import com.networknt.schema.InputFormat
import com.networknt.schema.JsonSchemaFactory
import com.networknt.schema.SchemaLocation
import com.networknt.schema.SpecVersion
import dev.vulnlog.lib.core.buildVexStatements
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty

/**
 * Conformance oracle: validates writer output against the official OpenVEX 0.2.0 JSON schema
 * (checked in under test resources).
 */
class OpenVexSchemaValidationTest :
    FunSpec({
        val factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012)
        val schema = factory.getSchema(SchemaLocation.of("classpath:openvex/openvex_json_schema.json"))

        test("the emitted document with every status and action variant conforms to the schema") {
            val document = writeDocument()

            val messages = schema.validate(document, InputFormat.JSON)

            messages.shouldBeEmpty()
        }

        test("an updated document with last_updated conforms to the schema") {
            val statements = buildVexStatements(vulnlogFile, release2)
            val document =
                OpenVexMapper.toDto(
                    project = project,
                    statements = statements,
                    documentId = DOCUMENT_ID,
                    version = 2,
                    timestamp = timestamp,
                    lastUpdated = timestamp.plusSeconds(86400),
                    toolVersion = TOOL_VERSION,
                )

            val messages = schema.validate(OpenVexWriter.write(document), InputFormat.JSON)

            messages.shouldBeEmpty()
        }
    })
