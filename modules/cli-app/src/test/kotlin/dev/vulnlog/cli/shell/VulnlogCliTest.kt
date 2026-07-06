// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.cli.shell

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.testing.test
import dev.vulnlog.lib.shell.DiagnosticLevel
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

private class ProbeCommand : CliktCommand(name = "probe") {
    var seen: Verbosity? = null

    override fun run() {
        seen = diagnostics().verbosity
    }
}

class VulnlogCliTest :
    FunSpec({

        fun cliWithProbe(): Pair<VulnlogCli, ProbeCommand> {
            val probe = ProbeCommand()
            return VulnlogCli().subcommands(probe) to probe
        }

        context("verbosity flags") {

            test("defaults to no diagnostics and status lines on") {
                val (cli, probe) = cliWithProbe()

                cli.test("probe").statusCode shouldBe 0

                probe.seen shouldBe Verbosity(level = 0, quiet = false)
            }

            test("-v enables verbose") {
                val (cli, probe) = cliWithProbe()

                cli.test("-v probe").statusCode shouldBe 0

                probe.seen shouldBe Verbosity(level = 1, quiet = false)
            }

            test("-vv enables debug") {
                val (cli, probe) = cliWithProbe()

                cli.test("-vv probe").statusCode shouldBe 0

                probe.seen shouldBe Verbosity(level = 2, quiet = false)
            }

            test("--verbose is the long form of -v") {
                val (cli, probe) = cliWithProbe()

                cli.test("--verbose probe").statusCode shouldBe 0

                probe.seen shouldBe Verbosity(level = 1, quiet = false)
            }

            test("--debug is an alias for -vv") {
                val (cli, probe) = cliWithProbe()

                cli.test("--debug probe").statusCode shouldBe 0

                probe.seen shouldBe Verbosity(level = 2, quiet = false)
            }

            test("-q sets quiet") {
                val (cli, probe) = cliWithProbe()

                cli.test("-q probe").statusCode shouldBe 0

                probe.seen shouldBe Verbosity(level = 0, quiet = true)
            }

            test("-q with -v is a usage error") {
                val (cli, _) = cliWithProbe()

                val result = cli.test("-q -v probe")

                result.statusCode shouldBe 1
                result.stderr shouldContain "Option --quiet cannot be combined with --verbose or --debug."
            }

            test("-q with --debug is a usage error") {
                val (cli, _) = cliWithProbe()

                val result = cli.test("-q --debug probe")

                result.statusCode shouldBe 1
                result.stderr shouldContain "Option --quiet cannot be combined with --verbose or --debug."
            }
        }

        context("Verbosity") {

            test("level 0 enables nothing") {
                Verbosity(level = 0).enables(DiagnosticLevel.VERBOSE).shouldBeFalse()
                Verbosity(level = 0).enables(DiagnosticLevel.DEBUG).shouldBeFalse()
            }

            test("level 1 enables verbose only") {
                Verbosity(level = 1).enables(DiagnosticLevel.VERBOSE).shouldBeTrue()
                Verbosity(level = 1).enables(DiagnosticLevel.DEBUG).shouldBeFalse()
            }

            test("level 2 enables verbose and debug") {
                Verbosity(level = 2).enables(DiagnosticLevel.VERBOSE).shouldBeTrue()
                Verbosity(level = 2).enables(DiagnosticLevel.DEBUG).shouldBeTrue()
            }

            test("stack traces require level 2") {
                Verbosity(level = 1).stackTraces.shouldBeFalse()
                Verbosity(level = 2).stackTraces.shouldBeTrue()
            }

            test("quiet disables status lines") {
                Verbosity(quiet = false).statusEnabled.shouldBeTrue()
                Verbosity(quiet = true).statusEnabled.shouldBeFalse()
            }
        }

        context("CliDiagnostics sink") {

            test("level 0 emits nothing") {
                val lines = mutableListOf<String>()

                val diagnostics = CliDiagnostics(Verbosity(level = 0), lines::add)
                diagnostics.sink.verbose("parsed")
                diagnostics.sink.debug("timing")

                lines shouldBe emptyList()
            }

            test("level 1 emits verbose only") {
                val lines = mutableListOf<String>()

                val diagnostics = CliDiagnostics(Verbosity(level = 1), lines::add)
                diagnostics.sink.verbose("parsed")
                diagnostics.sink.debug("timing")

                lines shouldBe listOf("verbose: parsed")
            }

            test("level 2 emits verbose and debug") {
                val lines = mutableListOf<String>()

                val diagnostics = CliDiagnostics(Verbosity(level = 2), lines::add)
                diagnostics.sink.verbose("parsed")
                diagnostics.sink.debug("timing")

                lines shouldBe listOf("verbose: parsed", "debug: timing")
            }
        }

        test("subcommand without a parent context falls back to defaults") {
            val probe = ProbeCommand()

            probe.test("").statusCode shouldBe 0

            probe.seen shouldBe Verbosity(level = 0, quiet = false)
        }
    })
