// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.cli.shell

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.UsageError
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.core.obj
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.parameters.options.counted
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.versionOption
import dev.vulnlog.cli.BuildInfo

fun main(args: Array<String>) = vulnlogCommand().main(args)

fun vulnlogCommand(): VulnlogCli =
    VulnlogCli()
        .subcommands(InitCommand())
        .subcommands(ValidateCommand())
        .subcommands(FmtCommand())
        .subcommands(SuppressCommand())
        .subcommands(ReportCommand())
        .subcommands(ModifyCommand())

class VulnlogCli : CliktCommand(name = "vulnlog") {
    init {
        versionOption(BuildInfo.VERSION)
    }

    private val verbose: Int by option(
        "-v",
        "--verbose",
        help = "Print verbose diagnostics on stderr. Repeat (-vv) for debug output.",
    ).counted()

    private val debug: Boolean by option("--debug", help = "Alias for -vv.").flag()

    private val quiet: Boolean by option(
        "-q",
        "--quiet",
        help = "Suppress status lines. Errors and warnings still print.",
    ).flag()

    var verbosity: Verbosity = Verbosity()
        private set

    override fun helpEpilog(context: Context): String =
        "Questions or feedback? Join the discussion at https://github.com/vulnlog/vulnlog/discussions"

    override fun run() {
        if (quiet && (verbose > 0 || debug)) {
            throw UsageError("Option --quiet cannot be combined with --verbose or --debug.")
        }
        verbosity = Verbosity(level = maxOf(verbose, if (debug) 2 else 0), quiet = quiet)
        currentContext.obj = CliDiagnostics(verbosity) { message -> echo(message, err = true) }
    }
}
