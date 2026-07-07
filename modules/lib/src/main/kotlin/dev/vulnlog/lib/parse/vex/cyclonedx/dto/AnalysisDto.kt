// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.cyclonedx.dto

import com.fasterxml.jackson.annotation.JsonInclude

data class AnalysisDto(
    val state: String,
    @param:JsonInclude(JsonInclude.Include.NON_NULL)
    val justification: String? = null,
    @param:JsonInclude(JsonInclude.Include.NON_NULL)
    val detail: String? = null,
)
