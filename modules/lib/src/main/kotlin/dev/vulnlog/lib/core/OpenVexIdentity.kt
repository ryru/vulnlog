// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.core

import java.time.Instant

/**
 * The identity of one OpenVEX document version: the stable `@id`, the version number, the original
 * issuance time, and the update time from version 2 onward.
 */
data class OpenVexIdentity(
    val id: String,
    val version: Int,
    val timestamp: Instant,
    val lastUpdated: Instant?,
)

/**
 * Decides the identity of the next document version. A [prior] identity is continued: the `@id`
 * and the original issuance time are kept, the version is incremented, and [now] becomes the
 * update time. Without a prior identity a new one starts at version 1, issued at [now], with no
 * update time; [newDocumentId] is invoked only in that case.
 */
fun nextOpenVexIdentity(
    prior: OpenVexIdentity?,
    newDocumentId: () -> String,
    now: Instant,
): OpenVexIdentity =
    prior?.copy(version = prior.version + 1, lastUpdated = now)
        ?: OpenVexIdentity(id = newDocumentId(), version = 1, timestamp = now, lastUpdated = null)
