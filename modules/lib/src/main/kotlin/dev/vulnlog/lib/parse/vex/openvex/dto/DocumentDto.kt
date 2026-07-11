// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.openvex.dto

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty

/**
 * OpenVEX 0.2.0 document envelope. Property order is the serialization order.
 */
data class DocumentDto(
    @param:JsonProperty("@context")
    val context: String,
    @param:JsonProperty("@id")
    val id: String,
    val author: String,
    val role: String,
    val timestamp: String,
    @param:JsonProperty("last_updated")
    @param:JsonInclude(JsonInclude.Include.NON_NULL)
    val lastUpdated: String? = null,
    val version: Int,
    val tooling: String,
    val statements: List<StatementDto>,
)
