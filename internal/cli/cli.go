package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/analyzer"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/app"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/capture"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/control"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/logging"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/terminal"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/version"
)

func New() *cobra.Command {
	c := config.Default()
	root := &cobra.Command{Use: "blackbox", Short: "A bounded kernel flight recorder for Linux production incidents", SilenceUsage: true, SilenceErrors: true, Version: version.String()}
	colorMode := "auto"
	var logger *slog.Logger
	root.PersistentFlags().StringVar(&colorMode, "color", "auto", "terminal colors: auto, always, never")
	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		if !terminal.ValidMode(colorMode) {
			return fmt.Errorf("color must be auto, always, or never")
		}
		configPath := ""
		if cmd.Flags().Lookup("config") != nil {
			var err error
			configPath, err = cmd.Flags().GetString("config")
			if err != nil {
				return err
			}
		}
		var err error
		c, err = config.Load(configPath, cmd.Flags())
		if err == nil && cmd.Name() == "capture" {
			c.AutoCapture.Enabled = false
		}
		if err == nil {
			logger = logging.New(c.LogLevel, cmd.ErrOrStderr())
		}
		return err
	}
	daemon := &cobra.Command{Use: "daemon", Args: cobra.NoArgs, Short: "Record bounded history in the foreground", RunE: func(cmd *cobra.Command, _ []string) error {
		e, er := app.NewWithLogger(c, logger)
		if er != nil {
			return er
		}
		defer e.Close()
		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()
		run := make(chan error, 1)
		server := make(chan error, 1)
		go func() { run <- e.Run(ctx) }()
		go func() { server <- control.Serve(ctx, c.Socket, e) }()
		logger.Info("recorder starting", "history", c.History, "max_memory", c.MaxMemory, "strict", c.Strict, "socket", c.Socket)
		select {
		case er = <-run:
			cancel()
			<-server
		case er = <-server:
			cancel()
			<-run
		case <-ctx.Done():
			cancel()
			er = <-run
			<-server
		}
		return er
	}}
	config.AddRecordingFlags(daemon.Flags())
	config.AddControlFlags(daemon.Flags())
	config.AddLoggingFlags(daemon.Flags())
	addConfigFlag(daemon)
	root.AddCommand(daemon)
	var asJSON, statusVerbose bool
	status := &cobra.Command{Use: "status", Args: cobra.NoArgs, Short: "Show recorder health and missing coverage", RunE: func(cmd *cobra.Command, _ []string) error {
		r, er := control.CallWithOptions(cmd.Context(), c.Socket, control.Request{Operation: "status"}, nil, c.Control)
		if er != nil {
			return er
		}
		if r.Health == nil {
			return fmt.Errorf("daemon returned no health")
		}
		h := *r.Health
		var outputErr error
		if asJSON {
			outputErr = writeJSON(cmd.OutOrStdout(), h)
		} else {
			outputErr = renderStatus(cmd.OutOrStdout(), h, terminal.For(cmd.OutOrStdout(), colorMode), statusVerbose)
		}
		if outputErr != nil {
			return outputErr
		}
		if _, active := sensorCounts(h); active == 0 {
			return fmt.Errorf("no active sensors")
		}
		return nil
	}}
	status.Flags().BoolVar(&statusVerbose, "verbose", false, "show all lifetime diagnostics")
	status.Flags().BoolVar(&asJSON, "json", false, "emit JSON health")
	config.AddControlFlags(status.Flags())
	root.AddCommand(status)
	var last time.Duration
	var output string
	snapshot := &cobra.Command{Use: "snapshot", Args: cobra.NoArgs, Short: "Freeze previous history into a private .bbx file", RunE: func(cmd *cobra.Command, _ []string) error {
		if output == "" {
			generated, err := newOutputPath("snapshot")
			if err != nil {
				return err
			}
			output = generated
		}
		if !cmd.Flags().Changed("last") {
			response, err := control.CallWithOptions(cmd.Context(), c.Socket, control.Request{Operation: "status"}, nil, c.Control)
			if err != nil {
				return err
			}
			last = c.History
			if response.Settings != nil && response.Settings.HistoryNS > 0 {
				last = time.Duration(response.Settings.HistoryNS)
			}
		}
		if last <= 0 {
			return fmt.Errorf("last must be positive")
		}
		er := capture.PublishWithContext(cmd.Context(), output, c.Capture, func(w io.Writer) error {
			_, er := control.CallWithOptions(cmd.Context(), c.Socket, control.Request{Operation: "snapshot", LastNS: int64(last)}, w, c.Control)
			return er
		})
		if er != nil {
			return fmt.Errorf("snapshot failed: %w", er)
		}
		return saved(cmd.OutOrStdout(), output, nil)
	}}
	snapshot.Flags().DurationVar(&last, "last", 0, "previous duration to freeze (unset: daemon history; older daemon: configured history)")
	snapshot.Flags().StringVarP(&output, "output", "o", "", "destination (default: generated in the current directory; must not exist)")
	config.AddControlFlags(snapshot.Flags())
	root.AddCommand(snapshot)
	var reportJSON, reportVerbose bool
	analyze := &cobra.Command{Use: "analyze FILE.bbx", Args: cobra.ExactArgs(1), Short: "Analyze a capture offline without root or eBPF", RunE: func(cmd *cobra.Command, args []string) error {
		recording, er := capture.ReadFileWithLimits(args[0], c.Capture)
		if er != nil {
			return er
		}
		r := analyzer.Analyze(recording)
		if reportJSON {
			return writeJSON(cmd.OutOrStdout(), r)
		}
		eventLimit, processLimit := c.Report.Events, c.Report.Processes
		if reportVerbose {
			eventLimit, processLimit = c.Report.VerboseEvents, c.Report.VerboseProcesses
		}
		return analyzer.RenderWithOptions(cmd.OutOrStdout(), r, analyzer.RenderOptions{Theme: terminal.For(cmd.OutOrStdout(), colorMode), Verbose: reportVerbose, EventLimit: eventLimit, ProcessLimit: processLimit})
	}}
	analyze.Flags().BoolVar(&reportVerbose, "verbose", false, "include lifetime diagnostics and expanded event/process limits")
	analyze.Flags().BoolVar(&reportJSON, "json", false, "emit the complete deterministic report as JSON")
	root.AddCommand(analyze)
	var duration time.Duration
	var captureOutput string
	record := &cobra.Command{Use: "capture", Args: cobra.NoArgs, Short: "Record a new window without an existing daemon", RunE: func(cmd *cobra.Command, _ []string) error {
		if duration < config.MinHistory || duration > config.MaxHistory {
			return fmt.Errorf("duration must be between 1s and 24h")
		}
		c.History = duration
		if err := c.Validate(); err != nil {
			return err
		}
		if err := ensureNoDaemon(cmd.Context(), c); err != nil {
			return err
		}
		if captureOutput == "" {
			generated, err := newOutputPath("capture")
			if err != nil {
				return err
			}
			captureOutput = generated
		}
		e, er := app.NewWithLogger(c, logger)
		if er != nil {
			return er
		}
		defer e.Close()
		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()
		run := make(chan error, 1)
		go func() { run <- e.Run(ctx) }()
		timer := time.NewTimer(duration)
		defer timer.Stop()
		select {
		case er = <-run:
			if er == nil {
				return ctx.Err()
			}
			return er
		case <-ctx.Done():
			cancel()
			<-run
			return ctx.Err()
		case <-timer.C:
		}
		result, er := e.Ask(ctx, duration)
		if result.ReleaseSnapshot != nil {
			defer result.ReleaseSnapshot()
		}
		cancel()
		runErr := <-run
		if er != nil {
			return er
		}
		if runErr != nil {
			return runErr
		}
		return saved(cmd.OutOrStdout(), captureOutput, capture.PublishWithContext(cmd.Context(), captureOutput, c.Capture, func(w io.Writer) error {
			return (capture.Container{Limits: c.Capture}).Write(w, result.Capture)
		}))
	}}
	record.Flags().DurationVar(&duration, "duration", config.DefaultCaptureDuration, "new recording window (sets retained history for this run)")
	record.Flags().StringVarP(&captureOutput, "output", "o", "", "destination (default: generated in the current directory; must not exist)")
	config.AddCaptureFlags(record.Flags())
	config.AddLoggingFlags(record.Flags())
	addConfigFlag(record)
	root.AddCommand(record)
	var demoOutput string
	demo := &cobra.Command{Use: "demo", Args: cobra.NoArgs, Short: "Create an explicitly synthetic capture for offline exploration", RunE: func(cmd *cobra.Command, _ []string) error {
		return saved(cmd.OutOrStdout(), demoOutput, capture.WriteFileWithLimits(demoOutput, app.Demo(), c.Capture))
	}}
	demo.Flags().StringVarP(&demoOutput, "output", "o", config.DefaultDemoOutput, "destination (must not exist)")
	root.AddCommand(demo)
	configCommand := &cobra.Command{Use: "config", Short: "Validate or print effective configuration"}
	check := &cobra.Command{Use: "check", Args: cobra.NoArgs, Short: "Validate merged settings without root or kernel access", RunE: func(cmd *cobra.Command, _ []string) error {
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "Configuration valid.")
		return err
	}}
	show := &cobra.Command{Use: "show", Args: cobra.NoArgs, Short: "Print effective configuration as YAML", RunE: func(cmd *cobra.Command, _ []string) error {
		b, err := config.YAML(c)
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(b)
		return err
	}}
	for _, command := range []*cobra.Command{check, show} {
		config.AddConfigFlags(command.Flags())
		addConfigFlag(command)
	}
	configCommand.AddCommand(check, show)
	root.AddCommand(configCommand, &cobra.Command{Use: "version", Args: cobra.NoArgs, Short: "Show the application build version", RunE: func(cmd *cobra.Command, _ []string) error {
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "Blackbox %s\n", version.String())
		return err
	}})
	return root
}

func addConfigFlag(command *cobra.Command) {
	command.Flags().String("config", "", "explicit YAML configuration file (no implicit discovery)")
}

func writeJSON(w io.Writer, v any) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(v)
}
func saved(w io.Writer, path string, err error) error {
	if err != nil {
		return err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve saved capture path: %w", err)
	}
	_, err = fmt.Fprintln(w, path)
	return err
}
