// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.core

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.time.Instant

private const val DOCUMENT_ID = "https://vulnlog.dev/vex/00000000-0000-0000-0000-000000000001"
private val issued = Instant.parse("2026-04-25T00:00:00Z")
private val now = Instant.parse("2026-05-01T12:34:56Z")

class OpenVexIdentityTest :
    FunSpec({
        test("without a prior identity a new one starts at version 1 without an update time") {
            val identity = nextOpenVexIdentity(prior = null, newDocumentId = { DOCUMENT_ID }, now = now)

            identity shouldBe OpenVexIdentity(DOCUMENT_ID, version = 1, timestamp = now, lastUpdated = null)
        }

        test("a prior identity keeps its id and issuance time, bumps the version, and records the update time") {
            val prior = OpenVexIdentity(DOCUMENT_ID, version = 3, timestamp = issued, lastUpdated = null)

            val identity = nextOpenVexIdentity(prior, newDocumentId = { error("must not be invoked") }, now = now)

            identity shouldBe OpenVexIdentity(DOCUMENT_ID, version = 4, timestamp = issued, lastUpdated = now)
        }
    })
