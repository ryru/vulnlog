// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.model.vex

import com.fasterxml.jackson.annotation.JsonValue
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit

/**
 * A point in time in the RFC 3339 UTC second precision form the VEX formats require, for example
 * `2026-04-25T00:00:00Z`. Wraps the instant so DTOs carry a typed timestamp instead of a bare
 * string. Construct through the factory functions; the constructor rejects sub-second precision.
 */
data class Rfc3339Timestamp(
    val instant: Instant,
) {
    init {
        require(instant.nano == 0) { "RFC 3339 timestamps carry second precision, got $instant" }
    }

    @JsonValue
    override fun toString(): String = instant.toString()

    companion object {
        /** Truncates the instant to second precision. */
        fun of(instant: Instant): Rfc3339Timestamp = Rfc3339Timestamp(instant.truncatedTo(ChronoUnit.SECONDS))

        /** Widens the date to midnight UTC. */
        fun of(date: LocalDate): Rfc3339Timestamp = of(date.atStartOfDay(ZoneOffset.UTC).toInstant())
    }
}
