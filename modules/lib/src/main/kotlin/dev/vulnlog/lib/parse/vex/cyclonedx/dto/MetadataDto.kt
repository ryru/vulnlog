// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.cyclonedx.dto

data class MetadataDto(
    val timestamp: String,
    val component: ComponentDto,
)
