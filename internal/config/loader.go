package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.yaml.in/yaml/v3"
)

// FlagKey connects CLI spelling to schema spelling without exposing Viper.
const FlagKey = "blackbox.config.key"

// Load creates an isolated merge context. No environment or implicit file lookup
// occurs. Only changed flags override a file; callers receive a validated value.
func Load(path string, flags *pflag.FlagSet) (Config, error) {
	v := viper.New()
	setDefaults(v, reflect.ValueOf(operatorSettings(Default())), "")
	if path != "" {
		b, err := readFile(path)
		if err != nil {
			return Config{}, err
		}
		values, err := strictYAML(b)
		if err != nil {
			return Config{}, fmt.Errorf("config %s: %w", path, err)
		}
		if err = v.MergeConfigMap(values); err != nil {
			return Config{}, err
		}
	}
	var bindErr error
	if flags != nil {
		flags.VisitAll(func(f *pflag.Flag) {
			if key := f.Annotations[FlagKey]; len(key) == 1 && bindErr == nil {
				bindErr = v.BindPFlag(key[0], f)
			}
		})
	}
	if bindErr != nil {
		return Config{}, bindErr
	}
	var result fileConfig
	hook := mapstructure.ComposeDecodeHookFunc(mapstructure.StringToTimeDurationHookFunc(), byteQuantityHook, mapstructure.StringToSliceHookFunc(","))
	if err := v.UnmarshalExact(&result, viper.DecodeHook(hook)); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	c, err := result.runtime()
	if err != nil {
		return Config{}, fmt.Errorf("validate config: %w", err)
	}
	return c, nil
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxConfigBytes {
		return nil, fmt.Errorf("config exceeds %d bytes", MaxConfigBytes)
	}
	return b, nil
}
func byteQuantityHook(from, to reflect.Type, value any) (any, error) {
	if from.Kind() == reflect.String && to.Kind() == reflect.Int64 && to != reflect.TypeFor[time.Duration]() {
		return Memory(value.(string))
	}
	return value, nil
}
func setDefaults(v *viper.Viper, value reflect.Value, prefix string) {
	typ := value.Type()
	for i := 0; i < value.NumField(); i++ {
		key := typ.Field(i).Tag.Get("mapstructure")
		if key == "" || key == "-" {
			continue
		}
		if prefix != "" {
			key = prefix + "." + key
		}
		field := value.Field(i)
		if field.Kind() == reflect.Struct {
			setDefaults(v, field, key)
		} else {
			v.SetDefault(key, field.Interface())
		}
	}
}

func strictYAML(b []byte) (map[string]any, error) {
	// SingleDocument means "ignore subsequent documents" in this API. Read the
	// stream explicitly so even an empty second document is rejected.
	loader := yaml.NewDecoder(bytes.NewReader(b))
	loader.KnownFields(true)
	var node yaml.Node
	if err := loader.Decode(&node); err != nil {
		return nil, fmt.Errorf("expected one config document: %w", err)
	}
	var second yaml.Node
	if err := loader.Decode(&second); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("multiple YAML documents are not allowed")
	}
	if len(node.Content) != 1 {
		return nil, fmt.Errorf("config must be a mapping")
	}
	if err := checkTypes(node.Content[0], reflect.TypeFor[fileConfig](), ""); err != nil {
		return nil, err
	}
	var values map[string]any
	if err := node.Decode(&values); err != nil {
		return nil, err
	}
	if memory, present := values["max_memory"]; present {
		if _, err := Memory(memory.(string)); err != nil {
			return nil, err
		}
	}
	return values, nil
}

// YAML decoders may coerce numbers/bools into strings. Validate the node types
// first so a typo cannot turn into a plausible but unintended configuration.
func checkTypes(n *yaml.Node, t reflect.Type, path string) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("%s: YAML anchors and aliases are not supported", path)
	}
	if n.Tag == "!!null" {
		return fmt.Errorf("%s: null is not a configuration value", path)
	}
	if t == reflect.TypeFor[time.Duration]() {
		if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
			return fmt.Errorf("%s must be a duration string", path)
		}
		_, err := time.ParseDuration(n.Value)
		return err
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			return fmt.Errorf("%s must be a mapping", path)
		}
		fields := yamlFields(t)
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			key, val := n.Content[i], n.Content[i+1]
			field, ok := fields[key.Value]
			if key.Tag != "!!str" || !ok {
				return fmt.Errorf("%s: unknown key %q", path, key.Value)
			}
			if seen[key.Value] {
				return fmt.Errorf("%s: duplicate key %q", path, key.Value)
			}
			seen[key.Value] = true
			name := key.Value
			if path != "" {
				name = path + "." + name
			}
			if err := checkTypes(val, field, name); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			return fmt.Errorf("%s must be a sequence", path)
		}
		for _, v := range n.Content {
			if err := checkTypes(v, t.Elem(), path); err != nil {
				return err
			}
		}
	default:
		tag := "!!int"
		if t.Kind() == reflect.String {
			tag = "!!str"
		}
		if t.Kind() == reflect.Bool {
			tag = "!!bool"
		}
		if n.Kind != yaml.ScalarNode || n.Tag != tag {
			return fmt.Errorf("%s has invalid type (expected %s)", path, strings.TrimPrefix(tag, "!!"))
		}
	}
	return nil
}
func yamlFields(t reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("yaml")
		if tag == ",inline" {
			for k, v := range yamlFields(f.Type) {
				fields[k] = v
			}
			continue
		}
		if tag != "" && tag != "-" {
			fields[tag] = f.Type
		}
	}
	return fields
}

// YAML renders the effective pre-release configuration.
func YAML(c Config) ([]byte, error) {
	node, err := settingsNode(c)
	if err != nil {
		return nil, err
	}
	return marshalNode(node)
}
