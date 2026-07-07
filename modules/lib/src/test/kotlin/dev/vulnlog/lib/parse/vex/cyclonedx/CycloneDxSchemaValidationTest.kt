// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.cyclonedx

import com.networknt.schema.InputFormat
import com.networknt.schema.JsonSchemaFactory
import com.networknt.schema.SchemaLocation
import com.networknt.schema.SpecVersion
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty

/**
 * Conformance oracle: validates writer output against the official CycloneDX 1.7 JSON schema
 * (checked in under test resources together with the schemas it references).
 */
class CycloneDxSchemaValidationTest :
    FunSpec({
        val factory =
            JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7) { builder ->
                builder.schemaMappers { mappers ->
                    mappers.mapPrefix("http://cyclonedx.org/schema", "classpath:cyclonedx")
                }
            }
        val schema = factory.getSchema(SchemaLocation.of("http://cyclonedx.org/schema/bom-1.7.schema.json"))

        test("the emitted document with every analysis state conforms to the schema") {
            val document = writeDocument()

            val messages = schema.validate(document, InputFormat.JSON)

            messages.shouldBeEmpty()
        }
    })
