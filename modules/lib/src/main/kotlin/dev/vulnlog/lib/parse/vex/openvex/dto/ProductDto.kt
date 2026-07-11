// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.openvex.dto

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty

data class ProductDto(
    @param:JsonProperty("@id")
    val id: String,
    val identifiers: IdentifiersDto,
    @param:JsonInclude(JsonInclude.Include.NON_EMPTY)
    val subcomponents: List<SubcomponentDto> = emptyList(),
)
