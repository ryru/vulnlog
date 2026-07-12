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
import com.github.ajalt.clikt.parameters.options.multiple
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.options.unique
import com.github.ajalt.clikt.parameters.types.choice
import dev.vulnlog.cli.BuildInfo
import dev.vulnlog.lib.core.StatusVerb
import dev.vulnlog.lib.core.buildVexStatements
import dev.vulnlog.lib.core.formatHint
import dev.vulnlog.lib.core.formatMessage
import dev.vulnlog.lib.core.formatStatus
import dev.vulnlog.lib.core.scopeReleaseToTags
import dev.vulnlog.lib.model.ReleaseEntry
import dev.vulnlog.lib.model.Tag
import dev.vulnlog.lib.model.VulnlogFile
import dev.vulnlog.lib.parse.vex.openvex.OpenVexDocumentResult
import dev.vulnlog.lib.parse.vex.openvex.generateOpenVexDocument
import dev.vulnlog.lib.result.Severity
import dev.vulnlog.lib.shell.FileInputOption
import dev.vulnlog.lib.shell.FileOutputOption
import dev.vulnlog.lib.shell.FilterValidationException
import dev.vulnlog.lib.shell.resolveTagsFilter
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
        help = "Output format of the VEX document. OpenVEX 0.2 is the default and only format.",
    ).choice("openvex")
        .default("openvex")

    val tags: Set<String> by option(
        "--tag",
        help =
            "Scope the document to the release purls carrying this tag (repeatable). " +
                "Statements stay in the document; only the product anchoring narrows.",
    ).multiple()
        .unique()

    val baseline: Path? by option(
        "--baseline",
        help =
            "Existing OpenVEX document to continue: its @id and timestamp are kept and its version " +
                "is incremented. Without this flag the document starts a new identity at version 1. " +
                "When the output path equals the baseline and the statements are unchanged, the file " +
                "is left untouched.",
    ).convert { Path.of(it) }

    val output: FileOutputOption by option(
        "-o",
        "--output",
        help = "Output file path, or '-' to write to stdout. Defaults to vex.json in the current directory.",
    ).convert(conversion = OptionCallTransformContext::toOutputFileOption)
        .default(FileOutputOption.File(Path.of("vex.json")))

    override fun run() {
        val parsedSuccessfully = parseInputOrFail(listOf(input))
        validateParsedInputOrFailWithFailureOutput(parsedSuccessfully)

        val vulnlogFile = parsedSuccessfully.values.first().content
        val targetRelease = resolveTargetReleaseOrFail(vulnlogFile)
        val documentTags = resolveDocumentTagsOrFail(vulnlogFile)
        val scopedRelease = scopeReleaseToTags(targetRelease, documentTags)

        if (scopedRelease.purls.isEmpty()) {
            failOnMissingPurls(scopedRelease, documentTags)
        }

        val statements = buildVexStatements(vulnlogFile, targetRelease.id, documentTags)
        if (statements.isEmpty()) {
            failOnEmptyStatements(targetRelease)
        }
        diagnosticSink().verbose(
            "generated ${statements.size} VEX statements for release '${targetRelease.id.value}'",
        )

        val baselineContent = baseline?.let(::readBaselineOrFail)
        val result =
            generateOpenVexDocument(
                project = vulnlogFile.project,
                statements = statements,
                baseline = baselineContent,
                newDocumentId = { "https://vulnlog.dev/vex/${UUID.randomUUID()}" },
                now = Instant.now(),
                toolVersion = BuildInfo.VERSION,
            )

        when (result) {
            OpenVexDocumentResult.Unchanged -> emitDocument(baselineContent.orEmpty(), unchanged = true)
            is OpenVexDocumentResult.Document -> emitDocument(result.content, unchanged = false)
        }
    }

    /**
     * Writes the document to the output target. An unchanged document whose output is the baseline
     * itself is already current on disk and is only reported, never rewritten.
     */
    private fun emitDocument(
        content: String,
        unchanged: Boolean,
    ) {
        when (val target = output) {
            is FileOutputOption.File ->
                if (unchanged && target.path.isSamePathAs(baseline)) {
                    echoStatus(formatStatus(StatusVerb.UNCHANGED, target.path.toString()))
                } else {
                    writeVexDocument(
                        { echoStatus(it) },
                        { echoMessage(it) },
                        target,
                        content,
                    )
                    diagnosticSink().verbose("wrote ${target.path}")
                }

            FileOutputOption.Stdout -> echo(content, trailingNewline = false)
        }
    }

    private fun Path.isSamePathAs(other: Path?): Boolean =
        other != null && toAbsolutePath().normalize() == other.toAbsolutePath().normalize()

    private fun readBaselineOrFail(path: Path): String {
        if (!path.exists()) {
            echoMessage(formatMessage(Severity.ERROR, "baseline file '$path' does not exist"))
            echoMessage(formatHint("point --baseline at an existing OpenVEX document, or drop the flag"))
            throw ProgramResult(ExitCode.INVALID_FLAG_VALUE.code)
        }
        return path.readText()
    }

    private fun resolveTargetReleaseOrFail(vulnlogFile: VulnlogFile): ReleaseEntry =
        try {
            resolveTargetRelease(release, vulnlogFile)
        } catch (e: FilterValidationException) {
            echoMessage(formatMessage(Severity.ERROR, e.message.orEmpty()))
            echoMessage(formatHint(e.detail))
            throw ProgramResult(ExitCode.INVALID_FLAG_VALUE.code)
        }

    private fun resolveDocumentTagsOrFail(vulnlogFile: VulnlogFile): Set<Tag> =
        try {
            resolveTagsFilter(tags, vulnlogFile)
        } catch (e: FilterValidationException) {
            echoMessage(formatMessage(Severity.ERROR, e.message.orEmpty()))
            echoMessage(formatHint(e.detail))
            throw ProgramResult(ExitCode.INVALID_FLAG_VALUE.code)
        }

    private fun failOnMissingPurls(
        release: ReleaseEntry,
        documentTags: Set<Tag>,
    ): Nothing {
        val scope =
            documentTags
                .takeIf { it.isNotEmpty() }
                ?.let { " tagged ${it.joinToString(", ") { tag -> "'${tag.value}'" }}" }
                .orEmpty()
        val nextStep =
            if (documentTags.isEmpty()) {
                "add at least one purl to the release so the VEX document can identify the product"
            } else {
                "tag a purl of the release with one of the requested tags, or drop --tag"
            }
        echoMessage(formatMessage(Severity.ERROR, "release '${release.id.value}' declares no purls$scope"))
        echoMessage(formatHint(nextStep))
        throw ProgramResult(ExitCode.VALIDATION_ERROR.code)
    }

    private fun failOnEmptyStatements(release: ReleaseEntry): Nothing {
        echoMessage(
            formatMessage(Severity.ERROR, "release '${release.id.value}' has no vulnerabilities to state"),
        )
        echoMessage(formatHint("an OpenVEX document needs at least one statement; record a vulnerability first"))
        throw ProgramResult(ExitCode.VALIDATION_ERROR.code)
    }
}
