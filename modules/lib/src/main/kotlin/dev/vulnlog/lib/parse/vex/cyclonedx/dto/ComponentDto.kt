// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.cyclonedx.dto

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty

data class ComponentDto(
    @param:JsonProperty("bom-ref")
    val bomRef: String,
    val type: String,
    val name: String,
    @param:JsonInclude(JsonInclude.Include.NON_NULL)
    val version: String? = null,
)
