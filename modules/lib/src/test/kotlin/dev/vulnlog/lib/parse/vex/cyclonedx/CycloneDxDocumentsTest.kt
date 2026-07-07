// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.cyclonedx

import dev.vulnlog.lib.core.buildVexStatements
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import java.time.Instant

private const val NEW_SERIAL_NUMBER = "urn:uuid:00000000-0000-0000-0000-000000000001"

private fun generate(
    existingOutput: String?,
    timestamp: Instant = Instant.parse("2026-04-25T00:00:00Z"),
    targetVulnerabilities: Int = Int.MAX_VALUE,
): CycloneDxDocumentResult {
    val file = vulnlogFile.copy(vulnerabilities = vulnlogFile.vulnerabilities.take(targetVulnerabilities))
    val statements = buildVexStatements(file, release2)
    return generateCycloneDxDocument(
        project = project,
        release = file.releases[1],
        statements = statements,
        existingOutput = existingOutput,
        newSerialNumber = { NEW_SERIAL_NUMBER },
        timestamp = timestamp,
    )
}

class CycloneDxDocumentsTest :
    FunSpec({
        test("without an existing output a new identity starts at version 1") {
            val result = generate(existingOutput = null)

            val document = result.shouldBeInstanceOf<CycloneDxDocumentResult.Document>()
            document.content shouldContain "\"serialNumber\": \"$NEW_SERIAL_NUMBER\""
            document.content shouldContain "\"version\": 1"
        }

        test("an unchanged document is not rewritten even when the generation time differs") {
            val first = generate(existingOutput = null).shouldBeInstanceOf<CycloneDxDocumentResult.Document>()

            val second = generate(existingOutput = first.content, timestamp = Instant.parse("2026-05-01T12:34:56Z"))

            second shouldBe CycloneDxDocumentResult.Unchanged
        }

        test("a changed document keeps the serial number and bumps the version") {
            val first =
                generate(existingOutput = null, targetVulnerabilities = 2)
                    .shouldBeInstanceOf<CycloneDxDocumentResult.Document>()

            val second = generate(existingOutput = first.content)

            val document = second.shouldBeInstanceOf<CycloneDxDocumentResult.Document>()
            document.content shouldContain "\"serialNumber\": \"$NEW_SERIAL_NUMBER\""
            document.content shouldContain "\"version\": 2"
        }

        test("an invalid existing output starts a new identity") {
            val result = generate(existingOutput = "not json at all {")

            val document = result.shouldBeInstanceOf<CycloneDxDocumentResult.Document>()
            document.content shouldContain "\"version\": 1"
        }

        test("an existing output that is no CycloneDX document starts a new identity") {
            val result = generate(existingOutput = """{"foo": "bar"}""")

            val document = result.shouldBeInstanceOf<CycloneDxDocumentResult.Document>()
            document.content shouldContain "\"serialNumber\": \"$NEW_SERIAL_NUMBER\""
            document.content shouldContain "\"version\": 1"
        }
    })
