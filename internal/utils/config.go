package utils

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Config captures runtime parameters for the transparent TLS proxy.
type Config struct {
	ListenAddr    string
	FirstFragment int
	GapMin        time.Duration
	GapMax        time.Duration
	ReadTimeout   time.Duration
	DialTimeout   time.Duration
	MaxRecordSize int
	Mark          int
	LogLevel      string
}

// NewRootCommand constructs the CLI root command backed by cobra and wires flag
// parsing into a Config value before invoking the provided run function.
func NewRootCommand(run func(Config) error) *cobra.Command {
	var (
		config        Config
		gapSpec       string
		readTimeoutMs int
		dialTimeoutMs int
	)

	cmd := &cobra.Command{
		Use:           "terasu-proxy",
		Short:         "Transparent TLS ClientHello record splitter",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			minGap, maxGap, err := parseGapRange(gapSpec)
			if err != nil {
				return err
			}
			config.GapMin = time.Duration(minGap) * time.Millisecond
			config.GapMax = time.Duration(maxGap) * time.Millisecond
			config.ReadTimeout = time.Duration(readTimeoutMs) * time.Millisecond
			config.DialTimeout = time.Duration(dialTimeoutMs) * time.Millisecond

			if err := validateConfig(&config); err != nil {
				return err
			}

			if run == nil {
				return errors.New("no run function provided")
			}
			return run(config)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&config.ListenAddr, "listen", ":15001", "transparent listen address (TPROXY target)")
	flags.IntVar(&config.FirstFragment, "first", 3, "number of bytes to place in the first TLS record fragment (>=0). 0 disables splitting")
	flags.IntVar(&config.MaxRecordSize, "max", 64*1024, "maximum TLS record payload to buffer for the first ClientHello record")
	flags.IntVar(&config.Mark, "mark", 0x66, "SO_MARK value applied to upstream connections")
	flags.StringVar(&config.LogLevel, "log-level", "info", "log level (debug, info, warn, error)")

	flags.StringVar(&gapSpec, "gap", "0,0", "gap range in milliseconds formatted as min,max (e.g. 1,10)")
	flags.IntVar(&readTimeoutMs, "rt", 250, "read timeout (ms) while waiting for the initial TLS record")
	flags.IntVar(&dialTimeoutMs, "dial", 5000, "upstream dial timeout in milliseconds")

	return cmd
}

func validateConfig(config *Config) error {
	if config == nil {
		return errors.New("config must not be nil")
	}
	if config.ListenAddr == "" {
		return errors.New("listen address must not be empty")
	}
	if config.FirstFragment < 0 {
		return errors.New("first fragment length must be >= 0")
	}
	if config.MaxRecordSize <= 0 {
		return errors.New("max record size must be positive")
	}
	if config.Mark < 0 {
		return errors.New("SO_MARK must be >= 0")
	}
	if config.GapMin < 0 || config.GapMax < 0 {
		return errors.New("gaps must not be negative")
	}
	if config.GapMin > config.GapMax {
		return errors.New("gap-min must not exceed gap-max")
	}
	if config.ReadTimeout <= 0 {
		return errors.New("read timeout must be positive")
	}
	if config.DialTimeout <= 0 {
		return errors.New("dial timeout must be positive")
	}

	config.LogLevel = strings.ToLower(strings.TrimSpace(config.LogLevel))
	switch config.LogLevel {
	case "debug", "info", "warn", "warning", "error":
		if config.LogLevel == "warning" {
			config.LogLevel = "warn"
		}
	default:
		return errors.New("unsupported log level")
	}

	return nil
}

func parseGapRange(spec string) (int, int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, 0, nil
	}
	parts := strings.Split(spec, ",")
	if len(parts) != 2 {
		return 0, 0, errors.New("gap must be formatted as min,max")
	}
	minStr := strings.TrimSpace(parts[0])
	maxStr := strings.TrimSpace(parts[1])
	if minStr == "" {
		minStr = "0"
	}
	if maxStr == "" {
		maxStr = "0"
	}
	minVal, err := strconv.Atoi(minStr)
	if err != nil {
		return 0, 0, errors.New("gap min must be an integer")
	}
	maxVal, err := strconv.Atoi(maxStr)
	if err != nil {
		return 0, 0, errors.New("gap max must be an integer")
	}
	if minVal < 0 || maxVal < 0 {
		return 0, 0, errors.New("gap values must be non-negative")
	}
	if maxVal != 0 && maxVal < minVal {
		return 0, 0, errors.New("gap max must not be less than min")
	}
	return minVal, maxVal, nil
}
