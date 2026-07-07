// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.cyclonedx

import dev.vulnlog.lib.parse.vex.cyclonedx.dto.BomDto
import tools.jackson.core.util.DefaultIndenter
import tools.jackson.core.util.DefaultPrettyPrinter
import tools.jackson.core.util.Separators
import tools.jackson.databind.SerializationFeature
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.kotlinModule

object CycloneDxWriter {
    private val indenter = DefaultIndenter("  ", "\n")

    private val prettyPrinter =
        DefaultPrettyPrinter(
            Separators
                .createDefaultInstance()
                .withObjectNameValueSpacing(Separators.Spacing.AFTER),
        ).withObjectIndenter(indenter)
            .withArrayIndenter(indenter)

    private val mapper =
        JsonMapper
            .builder()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .defaultPrettyPrinter(prettyPrinter)
            .addModule(kotlinModule())
            .build()

    fun write(bom: BomDto): String = mapper.writeValueAsString(bom) + "\n"
}
