// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.cli;

import pgp.wkd.cli.command.Fetch;
import picocli.CommandLine;

@CommandLine.Command(
        subcommands = {
                CommandLine.HelpCommand.class,
                Fetch.class
        }
)
public class WKDCLI {

    public static void main(String[] args) {
        int exitCode = execute(args);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    public static int execute(String[] args) {
        return new CommandLine(WKDCLI.class)
                .setCommandName("wkdcli")
                .execute(args);
    }
}
