// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.cli.shell

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.parameters.arguments.ArgumentTransformContext
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.arguments.convert
import com.github.ajalt.clikt.parameters.options.OptionCallTransformContext
import com.github.ajalt.clikt.parameters.options.convert
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.choice
import dev.vulnlog.lib.core.StatusVerb
import dev.vulnlog.lib.core.buildVexStatements
import dev.vulnlog.lib.core.formatHint
import dev.vulnlog.lib.core.formatMessage
import dev.vulnlog.lib.core.formatStatus
import dev.vulnlog.lib.model.ReleaseEntry
import dev.vulnlog.lib.model.VulnlogFile
import dev.vulnlog.lib.parse.vex.cyclonedx.CycloneDxDocumentResult
import dev.vulnlog.lib.parse.vex.cyclonedx.generateCycloneDxDocument
import dev.vulnlog.lib.result.Severity
import dev.vulnlog.lib.shell.FileInputOption
import dev.vulnlog.lib.shell.FileOutputOption
import dev.vulnlog.lib.shell.FilterValidationException
import dev.vulnlog.lib.shell.resolveTargetRelease
import java.nio.file.Path
import java.time.Instant
import java.util.UUID
import kotlin.io.path.exists
import kotlin.io.path.readText

class VexCommand : CliktCommand(name = "vex") {
    override fun help(context: Context): String = "Generate a VEX document for one release."

    val input: FileInputOption by argument(
        help = "Vulnlog file, or '-' to read from stdin, to generate the VEX document from.",
    ).convert(conversion = ArgumentTransformContext::toInputFileOption)

    val release: String by option(
        "--release",
        help = "Release to generate the VEX document for.",
    ).required()

    val format: String by option(
        "--format",
        help = "Output format of the VEX document. Currently only CycloneDX 1.7 is supported.",
    ).choice("cyclonedx")
        .required()

    val output: FileOutputOption by option(
        "-o",
        "--output",
        help =
            "Output file path, or '-' to write to stdout. Defaults to vex.cdx.json in the current directory. " +
                "An existing output file provides the document identity: its serial number is kept and its " +
                "version is incremented.",
    ).convert(conversion = OptionCallTransformContext::toOutputFileOption)
        .default(FileOutputOption.File(Path.of("vex.cdx.json")))

    override fun run() {
        val parsedSuccessfully = parseInputOrFail(listOf(input))
        validateParsedInputOrFailWithFailureOutput(parsedSuccessfully)

        val vulnlogFile = parsedSuccessfully.values.first().content
        val targetRelease = resolveTargetReleaseOrFail(vulnlogFile)

        if (targetRelease.purls.isEmpty()) {
            echoMessage(formatMessage(Severity.ERROR, "release '${targetRelease.id.value}' declares no purls"))
            echoMessage(formatHint("add at least one purl to the release so the VEX document can identify the product"))
            throw ProgramResult(ExitCode.VALIDATION_ERROR.code)
        }

        val statements = buildVexStatements(vulnlogFile, targetRelease.id)
        diagnosticSink().verbose(
            "generated ${statements.size} VEX statements for release '${targetRelease.id.value}'",
        )

        val existingOutput =
            (output as? FileOutputOption.File)?.path?.takeIf { it.exists() }?.readText()
        val result =
            generateCycloneDxDocument(
                project = vulnlogFile.project,
                release = targetRelease,
                statements = statements,
                existingOutput = existingOutput,
                newSerialNumber = { "urn:uuid:${UUID.randomUUID()}" },
                timestamp = Instant.now(),
            )

        when (result) {
            CycloneDxDocumentResult.Unchanged ->
                echoStatus(formatStatus(StatusVerb.UNCHANGED, (output as FileOutputOption.File).path.toString()))

            is CycloneDxDocumentResult.Document ->
                when (val target = output) {
                    is FileOutputOption.File -> {
                        writeVexDocument(
                            { echoStatus(it) },
                            { echoMessage(it) },
                            target,
                            result.content,
                        )
                        diagnosticSink().verbose("wrote ${target.path}")
                    }

                    FileOutputOption.Stdout -> echo(result.content, trailingNewline = false)
                }
        }
    }

    private fun resolveTargetReleaseOrFail(vulnlogFile: VulnlogFile): ReleaseEntry =
        try {
            resolveTargetRelease(release, vulnlogFile)
        } catch (e: FilterValidationException) {
            echoMessage(formatMessage(Severity.ERROR, e.message.orEmpty()))
            echoMessage(formatHint(e.detail))
            throw ProgramResult(ExitCode.INVALID_FLAG_VALUE.code)
        }
}
