// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.openvex.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class SubcomponentDto(
    @param:JsonProperty("@id")
    val id: String,
)
