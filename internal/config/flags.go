package config

import (
	"reflect"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

// AddFlags exposes the operator schema, never runtime implementation budgets.
func AddFlags(flags *pflag.FlagSet) { addFlags(flags, nil) }

// AddConfigFlags exposes settings accepted by YAML. Socket selection is kept
// on daemon control commands because it is a client/server endpoint choice.
func AddConfigFlags(flags *pflag.FlagSet) {
	addFlags(flags, func(key string) bool { return key != "socket" })
}
func AddRecordingFlags(flags *pflag.FlagSet) {
	addFlags(flags, func(key string) bool { return key != "log_level" && key != "socket" && key != "timeout" })
}
func AddCaptureFlags(flags *pflag.FlagSet) {
	addFlags(flags, func(key string) bool {
		return key != "log_level" && key != "socket" && key != "timeout" && key != "history"
	})
}
func AddControlFlags(flags *pflag.FlagSet) {
	addFlags(flags, func(key string) bool { return key == "socket" || key == "timeout" })
}
func AddLoggingFlags(flags *pflag.FlagSet) {
	addFlags(flags, func(key string) bool { return key == "log_level" })
}

func addFlags(flags *pflag.FlagSet, include func(string) bool) {
	var walk func(reflect.Value, string)
	walk = func(value reflect.Value, prefix string) {
		typ := value.Type()
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			key := typ.Field(i).Tag.Get("mapstructure")
			if key == "" || key == "-" {
				continue
			}
			if prefix != "" {
				key = prefix + "." + key
			}
			if field.Kind() == reflect.Struct {
				walk(field, key)
				continue
			}
			if include != nil && !include(key) {
				continue
			}
			name := strings.NewReplacer("_", "-", ".", "-").Replace(strings.TrimPrefix(key, "thresholds."))
			help := strings.ReplaceAll(settingHelp[key], "\n", " ")
			if field.Type() == reflect.TypeFor[time.Duration]() {
				flags.Duration(name, field.Interface().(time.Duration), help)
				flags.Lookup(name).DefValue = DurationText(field.Interface().(time.Duration))
			} else {
				switch field.Kind() {
				case reflect.Bool:
					flags.Bool(name, field.Bool(), help)
				case reflect.String:
					flags.String(name, field.String(), help)
				case reflect.Slice:
					flags.StringSlice(name, field.Interface().([]string), help)
				}
			}
			flags.SetAnnotation(name, FlagKey, []string{key})
		}
	}
	walk(reflect.ValueOf(operatorSettings(Default())), "")
}
