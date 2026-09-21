// Package terminal formats human CLI output; analysis and stored data stay unstyled.
package terminal

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"unicode"
	"unicode/utf8"
)

type Tone uint8

const (
	Neutral Tone = iota
	Good
	Warning
	Critical
	Info
	Muted
)

// Presentation defaults are contributor choices; Theme.Width supports callers
// selecting an explicit width. Automatic detection keeps long lines bounded.
const (
	MinWidth     = 40
	DefaultWidth = 80
	MaxAutoWidth = 100
)

type Theme struct {
	Color bool
	Width int
}

func ValidMode(mode string) bool { return mode == "auto" || mode == "always" || mode == "never" }
func For(w io.Writer, mode string) Theme {
	fd, ok := w.(interface{ Fd() uintptr })
	color := mode == "always"
	width := DefaultWidth
	if ok {
		if n := columns(fd.Fd()); n > 0 {
			width = min(MaxAutoWidth, max(MinWidth, n))
		}
		if mode == "auto" {
			color = isTerminal(fd.Fd()) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
		}
	}
	return Theme{Color: color, Width: width}
}
func (t Theme) width() int {
	if t.Width == 0 {
		return DefaultWidth
	}
	return max(MinWidth, t.Width)
}
func (t Theme) Paint(tone Tone, s string) string {
	if !t.Color || tone == Neutral {
		return s
	}
	code := "0"
	switch tone {
	case Good:
		code = "1;32"
	case Warning:
		code = "1;33"
	case Critical:
		code = "1;31"
	case Info:
		code = "1;36"
	case Muted:
		code = "2"
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
func Mark(tone Tone) string {
	switch tone {
	case Good:
		return "✓"
	case Warning:
		return "!"
	case Critical:
		return "✕"
	case Info:
		return "?"
	default:
		return "·"
	}
}
func (t Theme) Panel(w io.Writer, tone Tone, title string, lines ...string) {
	width := t.width() - 4
	fmt.Fprintln(w, t.Paint(Info, "╭─ BLACKBOX "+strings.Repeat("─", t.width()-13)+"╮"))
	for _, line := range Wrap(Mark(tone)+" "+title, width) {
		fmt.Fprintln(w, t.Paint(Info, "│ ")+t.Paint(tone, line)+strings.Repeat(" ", max(0, width-utf8.RuneCountInString(line)))+t.Paint(Info, " │"))
	}
	for _, s := range lines {
		for _, line := range Wrap(s, width) {
			fmt.Fprintln(w, t.Paint(Info, "│ ")+line+strings.Repeat(" ", max(0, width-utf8.RuneCountInString(line)))+t.Paint(Info, " │"))
		}
	}
	fmt.Fprintln(w, t.Paint(Info, "╰"+strings.Repeat("─", t.width()-2)+"╯"))
}
func (t Theme) Section(w io.Writer, title string) {
	fmt.Fprintln(w, "\n"+t.Paint(Info, "  "+title+" "+strings.Repeat("─", max(0, t.width()-utf8.RuneCountInString(title)-3))))
}
func (t Theme) Line(w io.Writer, tone Tone, indent, s string) {
	for _, line := range Wrap(s, t.width()-utf8.RuneCountInString(indent)) {
		fmt.Fprintln(w, indent+t.Paint(tone, line))
	}
}
func (t Theme) Notice(w io.Writer, tone Tone, title string, lines ...string) {
	t.Line(w, tone, "  ", Mark(tone)+" "+title)
	for _, line := range lines {
		t.Line(w, Neutral, "    ", line)
	}
}

// Table measures plain text before coloring, so ANSI codes cannot shift columns.
func (t Theme) Table(w io.Writer, header string, rows []string, tones []Tone) {
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, cleanCells(header))
	for _, row := range rows {
		fmt.Fprintln(tw, cleanCells(row))
	}
	tw.Flush()
	// Wide endpoints or a narrow terminal should remain readable instead of
	// wrapping aligned columns unpredictably. Fall back to labeled rows.
	for _, line := range strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n") {
		if utf8.RuneCountInString(line)+2 > t.width() {
			headers := strings.Split(cleanCells(header), "\t")
			for i, row := range rows {
				if i > 0 {
					fmt.Fprintln(w)
				}
				cells := strings.Split(cleanCells(row), "\t")
				fields := make([]string, 0, len(cells))
				for j, cell := range cells {
					label := ""
					if j < len(headers) {
						label = headers[j] + ": "
					}
					fields = append(fields, label+cell)
				}
				tone := Neutral
				if i < len(tones) {
					tone = tones[i]
				}
				t.Line(w, tone, "  ", strings.Join(fields, " · "))
			}
			return
		}
	}
	for i, line := range strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n") {
		tone := Neutral
		if i == 0 {
			tone = Muted
		} else if i-1 < len(tones) {
			tone = tones[i-1]
		}
		fmt.Fprintln(w, "  "+t.Paint(tone, line))
	}
}
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}
func Wrap(s string, width int) []string {
	width = max(1, width)
	var lines []string
	line := ""
	for _, word := range strings.Fields(Clean(s)) {
		if line != "" && utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) > width {
			lines = append(lines, line)
			line = ""
		}
		for utf8.RuneCountInString(word) > width {
			if line != "" {
				lines = append(lines, line)
				line = ""
			}
			r := []rune(word)
			lines = append(lines, string(r[:width]))
			word = string(r[width:])
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}
func Count(n uint64) string {
	s := fmt.Sprintf("%d", n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
func Sensor(s string) string {
	switch s {
	case "block_io":
		return "Block I/O"
	case "scheduler":
		return "Scheduler"
	case "tcp":
		return "TCP"
	case "oom":
		return "OOM"
	default:
		return Clean(s)
	}
}

func cleanCells(row string) string {
	cells := strings.Split(row, "\t")
	for i := range cells {
		cells[i] = Clean(cells[i])
	}
	return strings.Join(cells, "\t")
}
