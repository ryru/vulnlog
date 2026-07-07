// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.v1.dto

import com.fasterxml.jackson.annotation.JsonInclude

data class ReleasePurlEntryDto(
    val purl: String,
    @param:JsonInclude(JsonInclude.Include.NON_NULL)
    val tags: List<String>? = null,
)
