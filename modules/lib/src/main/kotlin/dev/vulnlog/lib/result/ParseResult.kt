// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.result

import dev.vulnlog.lib.model.ParseValidationVersion
import dev.vulnlog.lib.model.SourceLocation
import dev.vulnlog.lib.model.VulnlogFile
import dev.vulnlog.lib.model.VulnlogFileRaw
import java.io.File

sealed interface ParseResult {
    data class Ok(
        val validationVersion: ParseValidationVersion,
        val content: VulnlogFile,
        val rawContent: VulnlogFileRaw,
    ) : ParseResult

    data class Error(
        val error: String,
        val location: SourceLocation? = null,
    ) : ParseResult
}

data class ParseResults(
    val success: Map<File, ParseResult.Ok> = emptyMap(),
    val failure: Map<File, ParseResult.Error> = emptyMap(),
)
