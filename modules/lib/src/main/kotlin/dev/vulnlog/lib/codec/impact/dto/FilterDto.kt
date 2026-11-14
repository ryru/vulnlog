// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.codec.impact.dto

import com.fasterxml.jackson.annotation.JsonInclude

// Leaves out missing values and empty lists, which make up a large part of a big report.
@JsonInclude(JsonInclude.Include.NON_EMPTY)
data class FilterDto(
    val asOf: String?,
    val tags: List<String>,
    val reporter: String?,
    val states: List<String>,
    val verdicts: List<String>,
    val dispositions: List<String>,
)
