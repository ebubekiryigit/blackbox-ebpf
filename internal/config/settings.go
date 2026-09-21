package config

import (
	"bytes"
	"reflect"
	"strconv"
	"time"

	"go.yaml.in/yaml/v3"
)

// fileConfig is the complete operator surface. Runtime Config also carries
// implementation budgets, which cannot be set through YAML or CLI flags.
type fileConfig struct {
	LogLevel     string        `yaml:"log_level" mapstructure:"log_level"`
	History      time.Duration `yaml:"history" mapstructure:"history"`
	MaxMemory    string        `yaml:"max_memory" mapstructure:"max_memory"`
	Sensors      []string      `yaml:"sensors" mapstructure:"sensors"`
	Strict       bool          `yaml:"strict" mapstructure:"strict"`
	PollInterval time.Duration `yaml:"poll_interval" mapstructure:"poll_interval"`
	Timeout      time.Duration `yaml:"timeout" mapstructure:"timeout"`
	// Socket is a CLI-only endpoint override. Keeping it in the merge struct
	// lets Viper bind --socket without making it part of the YAML schema.
	Socket     string     `yaml:"-" mapstructure:"socket"`
	Thresholds thresholds `yaml:"thresholds" mapstructure:"thresholds"`
}

type thresholds struct {
	BlockIO   latencyLevels `yaml:"block_io" mapstructure:"block_io"`
	Scheduler latencyLevels `yaml:"scheduler" mapstructure:"scheduler"`
}
type latencyLevels struct {
	Warn     time.Duration `yaml:"warn" mapstructure:"warn"`
	Critical time.Duration `yaml:"critical" mapstructure:"critical"`
}

func operatorSettings(c Config) fileConfig {
	return fileConfig{
		LogLevel: c.LogLevel, History: c.History,
		MaxMemory: MemoryText(c.MaxMemory), Sensors: append([]string(nil), c.Enabled...),
		Strict: c.Strict, PollInterval: c.Resources.PollInterval,
		Timeout: c.Control.Timeout, Socket: c.Socket,
		Thresholds: thresholds{latencyLevels{c.BlockThreshold, c.BlockCritical}, latencyLevels{c.SchedulerThreshold, c.SchedulerCritical}},
	}
}

func (s fileConfig) runtime() (Config, error) {
	c := Default()
	memory, err := Memory(s.MaxMemory)
	if err != nil {
		return Config{}, err
	}
	c.LogLevel, c.History, c.MaxMemory = s.LogLevel, s.History, memory
	c.Enabled, c.Strict, c.Socket = append([]string(nil), s.Sensors...), s.Strict, s.Socket
	c.Resources.PollInterval = s.PollInterval
	c.Control.Timeout = s.Timeout
	// Selection, serialization and transport share one operator-visible deadline.
	c.Control.QueryTimeout = s.Timeout
	c.Control.DialTimeout = min(c.Control.DialTimeout, s.Timeout)
	c.BlockThreshold, c.BlockCritical = s.Thresholds.BlockIO.Warn, s.Thresholds.BlockIO.Critical
	c.SchedulerThreshold, c.SchedulerCritical = s.Thresholds.Scheduler.Warn, s.Thresholds.Scheduler.Critical
	return c, c.Validate()
}

// ExampleYAML adds descriptions and accepted values to every operator setting.
func ExampleYAML() ([]byte, error) {
	node, err := settingsNode(Default())
	if err != nil {
		return nil, err
	}
	var annotate func(*yaml.Node, string)
	annotate = func(n *yaml.Node, prefix string) {
		if n.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i < len(n.Content); i += 2 {
			key, value := n.Content[i], n.Content[i+1]
			name := prefix + key.Value
			key.HeadComment = settingHelp[name]
			annotate(value, name+".")
		}
	}
	annotate(node, "")
	return marshalNode(node)
}

func settingsNode(c Config) (*yaml.Node, error) {
	var node yaml.Node
	if err := node.Encode(operatorSettings(c)); err != nil {
		return nil, err
	}
	compactDurationNodes(&node, reflect.TypeFor[fileConfig]())
	return &node, nil
}

func marshalNode(node *yaml.Node) ([]byte, error) {
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(node); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func compactDurationNodes(node *yaml.Node, typ reflect.Type) {
	if typ == reflect.TypeFor[time.Duration]() {
		if value, err := time.ParseDuration(node.Value); err == nil {
			node.Value = DurationText(value)
		}
		return
	}
	if typ.Kind() != reflect.Struct || node.Kind != yaml.MappingNode {
		return
	}
	fields := yamlFields(typ)
	for i := 0; i < len(node.Content); i += 2 {
		if field, ok := fields[node.Content[i].Value]; ok {
			compactDurationNodes(node.Content[i+1], field)
		}
	}
}

// DurationText keeps generated configuration and help compact without changing
// the duration syntax accepted from operators.
func DurationText(value time.Duration) string {
	for _, unit := range []struct {
		duration time.Duration
		suffix   string
	}{{time.Hour, "h"}, {time.Minute, "m"}, {time.Second, "s"}} {
		if value != 0 && value%unit.duration == 0 {
			return strconv.FormatInt(int64(value/unit.duration), 10) + unit.suffix
		}
	}
	return value.String()
}

var settingHelp = map[string]string{
	"log_level":                     "Daemon log verbosity: debug, info, warn, error. Logs go to stderr.",
	"history":                       "Rolling history to keep: 1s–24h. Examples: 30s, 5m, 1h.",
	"max_memory":                    "Retained history budget: 1MiB–1GiB (B, KiB, MiB, GiB).\nTotal process memory also includes queues, Go runtime and snapshot work; kernel maps are separate.",
	"sensors":                       "Enabled sensors: block_io, scheduler, tcp, oom. Choose one or more; no duplicates.",
	"strict":                        "false: continue with available sensors and report missing coverage.\ntrue: fail startup or stop recording if any enabled sensor fails permanently.",
	"poll_interval":                 "How often to collect sensor totals: 100ms–1m, no longer than history.\nShorter intervals improve time resolution and increase polling work.",
	"timeout":                       "Maximum local control request/snapshot duration: 1s–10m. Examples: 30s, 1m.",
	"socket":                        "Private daemon socket. Absolute Unix path, at most 103 bytes.\nKeep the default unless running multiple daemons; clients must use the same path.",
	"thresholds":                    "Latency thresholds. Durations must be positive; critical must exceed warn.\nWarn selects slow-event details; critical raises report severity. Neither establishes a root cause.",
	"thresholds.block_io":           "Device I/O request latency (not application request duration).",
	"thresholds.block_io.warn":      "Slow I/O threshold. Example: 50ms.",
	"thresholds.block_io.critical":  "Critical I/O threshold. Example: 250ms.",
	"thresholds.scheduler":          "Runnable-to-running wait (not CPU execution time).",
	"thresholds.scheduler.warn":     "Slow runnable wait threshold. Example: 20ms.",
	"thresholds.scheduler.critical": "Critical runnable wait threshold. Example: 100ms.",
}
