// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.cyclonedx.dto

/**
 * CycloneDX 1.7 BOM envelope carrying VEX data. Covers the V1 field set of the VEX concept;
 * property order is the serialization order.
 */
data class BomDto(
    val bomFormat: String,
    val specVersion: String,
    val serialNumber: String,
    val version: Int,
    val metadata: MetadataDto,
    val components: List<ComponentDto>,
    val vulnerabilities: List<VulnerabilityDto>,
)
