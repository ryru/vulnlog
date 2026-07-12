// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.model.vex

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.time.Instant
import java.time.LocalDate

class Rfc3339TimestampTest :
    FunSpec({
        test("an instant is truncated to second precision") {
            val timestamp = Rfc3339Timestamp.of(Instant.parse("2026-04-25T12:34:56.789Z"))

            timestamp.toString() shouldBe "2026-04-25T12:34:56Z"
        }

        test("a date widens to midnight UTC") {
            val timestamp = Rfc3339Timestamp.of(LocalDate.of(2026, 4, 25))

            timestamp.toString() shouldBe "2026-04-25T00:00:00Z"
        }

        test("equal points in time are equal timestamps") {
            Rfc3339Timestamp.of(LocalDate.of(2026, 4, 25)) shouldBe
                Rfc3339Timestamp.of(Instant.parse("2026-04-25T00:00:00Z"))
        }

        test("the constructor rejects sub-second precision") {
            shouldThrow<IllegalArgumentException> {
                Rfc3339Timestamp(Instant.parse("2026-04-25T12:34:56.789Z"))
            }
        }
    })
