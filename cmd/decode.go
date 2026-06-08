package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/share"
)

func init() {
	rootCmd.AddCommand(decodeCmd)
	decodeCmd.Flags().Bool("json", false, "print the decoded report as raw JSON instead of a readable summary")
}

var decodeCmd = &cobra.Command{
	Use:   "decode [file]",
	Short: "Decode a shared DSD report blob into a readable diagnosis",
	Long: `Decode a report blob produced by ` + "`dsd health --blob`" + ` back into a
readable diagnosis. The blob is the network-optional way to move a report off a
host whose network is broken: the operator runs ` + "`dsd health --blob`" + ` and
sends you the text block (over chat/email, from a working machine), and you paste
it here.

Reads the blob from a file argument, or from stdin when no file is given:

  dsd decode report.txt
  pbpaste | dsd decode          # macOS
  xclip -o | dsd decode         # Linux
  dsd decode                    # paste, then Ctrl-D

Surrounding chat/email text and quote ("> ") prefixes are tolerated — only the
text between the BEGIN/END markers is used.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runDecode,
}

func runDecode(cmd *cobra.Command, args []string) error {
	var raw []byte
	var err error
	if len(args) == 1 && args[0] != "-" {
		raw, err = os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("decode: %w", err)
		}
	} else {
		raw, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("decode: reading stdin: %w", err)
		}
	}

	reportJSON, err := share.Decode(string(raw))
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	if jsonOut, _ := cmd.Flags().GetBool("json"); jsonOut {
		_, _ = os.Stdout.Write(reportJSON)
		if len(reportJSON) > 0 && reportJSON[len(reportJSON)-1] != '\n' {
			fmt.Println()
		}
		return nil
	}

	var report render.JSONOutput
	if err := json.Unmarshal(reportJSON, &report); err != nil {
		return fmt.Errorf("decode: report payload is not valid dsd JSON: %w", err)
	}
	fmt.Print(render.RenderReportText(report))
	return nil
}
