// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.openvex

import dev.vulnlog.lib.core.buildVexStatements
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.types.shouldBeInstanceOf
import java.time.Instant

private const val NEW_DOCUMENT_ID = "https://vulnlog.dev/vex/00000000-0000-0000-0000-000000000001"

private fun generate(
    baseline: String?,
    now: Instant = Instant.parse("2026-04-25T00:00:00Z"),
    targetVulnerabilities: Int = Int.MAX_VALUE,
): OpenVexDocumentResult {
    val file = vulnlogFile.copy(vulnerabilities = vulnlogFile.vulnerabilities.take(targetVulnerabilities))
    val statements = buildVexStatements(file, release2)
    return generateOpenVexDocument(
        project = project,
        statements = statements,
        baseline = baseline,
        newDocumentId = { NEW_DOCUMENT_ID },
        now = now,
        toolVersion = TOOL_VERSION,
    )
}

class OpenVexDocumentsTest :
    FunSpec({
        test("without a baseline a new identity starts at version 1 without last_updated") {
            val result = generate(baseline = null)

            val document = result.shouldBeInstanceOf<OpenVexDocumentResult.Document>()
            document.content shouldContain "\"@id\": \"$NEW_DOCUMENT_ID\""
            document.content shouldContain "\"version\": 1"
            document.content shouldNotContain "\"last_updated\""
        }

        test("a document equal to the baseline reports unchanged even when the generation time differs") {
            val first = generate(baseline = null).shouldBeInstanceOf<OpenVexDocumentResult.Document>()

            val second = generate(baseline = first.content, now = Instant.parse("2026-05-01T12:34:56Z"))

            second shouldBe OpenVexDocumentResult.Unchanged
        }

        test("a changed document keeps the id and timestamp, bumps the version, and sets last_updated") {
            val first =
                generate(baseline = null, targetVulnerabilities = 2)
                    .shouldBeInstanceOf<OpenVexDocumentResult.Document>()

            val second = generate(baseline = first.content, now = Instant.parse("2026-05-01T12:34:56Z"))

            val document = second.shouldBeInstanceOf<OpenVexDocumentResult.Document>()
            document.content shouldContain "\"@id\": \"$NEW_DOCUMENT_ID\""
            document.content shouldContain "\"timestamp\": \"2026-04-25T00:00:00Z\""
            document.content shouldContain "\"last_updated\": \"2026-05-01T12:34:56Z\""
            document.content shouldContain "\"version\": 2"
        }

        test("an invalid baseline starts a new identity") {
            val result = generate(baseline = "not json at all {")

            val document = result.shouldBeInstanceOf<OpenVexDocumentResult.Document>()
            document.content shouldContain "\"version\": 1"
        }

        test("a baseline that is no OpenVEX document starts a new identity") {
            val result = generate(baseline = """{"foo": "bar"}""")

            val document = result.shouldBeInstanceOf<OpenVexDocumentResult.Document>()
            document.content shouldContain "\"@id\": \"$NEW_DOCUMENT_ID\""
            document.content shouldContain "\"version\": 1"
        }
    })
