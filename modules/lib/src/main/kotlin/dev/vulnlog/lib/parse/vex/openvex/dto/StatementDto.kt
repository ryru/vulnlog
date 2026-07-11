// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.openvex.dto

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty

data class StatementDto(
    val vulnerability: VulnerabilityDto,
    val timestamp: String,
    val products: List<ProductDto>,
    val status: String,
    @param:JsonInclude(JsonInclude.Include.NON_NULL)
    val justification: String? = null,
    @param:JsonProperty("impact_statement")
    @param:JsonInclude(JsonInclude.Include.NON_NULL)
    val impactStatement: String? = null,
    @param:JsonProperty("action_statement")
    @param:JsonInclude(JsonInclude.Include.NON_NULL)
    val actionStatement: String? = null,
    @param:JsonProperty("action_statement_timestamp")
    @param:JsonInclude(JsonInclude.Include.NON_NULL)
    val actionStatementTimestamp: String? = null,
    @param:JsonProperty("status_notes")
    @param:JsonInclude(JsonInclude.Include.NON_NULL)
    val statusNotes: String? = null,
    @param:JsonInclude(JsonInclude.Include.NON_NULL)
    val supplier: String? = null,
)
