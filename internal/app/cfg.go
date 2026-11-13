package app

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config"

	"tule.dev/mailbox/internal/services/mailbox/sqlimpl"
)

// hstsSettings configures the Strict-Transport-Security header. It is only
// sent when MaxAge is set, so plain-HTTP deployments can leave it out.
type hstsSettings struct {
	MaxAge time.Duration
}

// authSettings holds the root key the server accepts. Every request must be
// SigV4-signed with it, so both key fields are required. IdentityEndpoint is
// the identity service's base URL, or empty to run standalone: set, a key
// identity issued is accepted too, and identity is asked with the root key,
// which must therefore be identity's root key as well.
type authSettings struct {
	AccessKeyID      string
	SecretAccessKey  string
	IdentityEndpoint string
}

// errNoCredentials is returned when the access key is not configured.
var errNoCredentials = errors.New("config: TULE_Auth_AccessKeyID and " +
	"TULE_Auth_SecretAccessKey must be set; every request is verified against them")

// Config is the bound application configuration. It keeps the store it was
// bound from, which the app registers as the gas.ConfigProvider so services
// can read settings Config itself does not model.
type Config struct {
	HSTS  *hstsSettings
	Auth  *authSettings
	Store *sqlimpl.Settings `validate:"required"`

	store gas.ConfigProvider
	Env   config.Environment
}

const (
	envVarSeparator = "_"
	envVarPrefix    = "TULE_"
)

// LoadConfig loads configuration from a .env file and then the process
// environment, the later source winning.
func LoadConfig() (*Config, error) {
	return LoadConfigFrom(
		config.NewDotEnvProvider(
			config.WithDotEnvSeparator(envVarSeparator),
			config.WithDotEnvFileNotFoundPanic(false),
		),
		config.NewEnvProvider(
			config.WithEnvSeparator(envVarSeparator),
			config.WithEnvPrefix(envVarPrefix),
		),
	)
}

// LoadConfigFrom loads configuration from the given providers in order, then
// applies the same defaults and binding as LoadConfig. Tests use it to inject
// a provider of their own.
func LoadConfigFrom(provs ...config.Provider) (*Config, error) {
	env := config.NewEnvExtension()

	opts := make([]config.Option, 0, len(provs)+1)
	opts = append(opts, config.WithExtension(env))

	for _, p := range provs {
		opts = append(opts, config.WithProvider(p))
	}

	store := config.New(opts...)

	if err := store.Load(); err != nil {
		return nil, fmt.Errorf("config: load: %w", err)
	}

	return bindConfig(store, env.Current())
}

func bindConfig(store gas.ConfigProvider, env config.Environment) (*Config, error) {
	if err := applyDefaults(store); err != nil {
		return nil, err
	}

	cfg := Config{Env: env, store: store}
	if err := store.Bind(&cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if cfg.Auth == nil || cfg.Auth.AccessKeyID == "" || cfg.Auth.SecretAccessKey == "" {
		return nil, errNoCredentials
	}
	if err := checkIdentityEndpoint(cfg.Auth.IdentityEndpoint); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// checkIdentityEndpoint holds the identity endpoint, when set, to an
// absolute http or https URL.
func checkIdentityEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("config: Auth.IdentityEndpoint %q is not an http or https URL",
			endpoint)
	}
	return nil
}

func applyDefaults(store gas.ConfigProvider) error {
	var errs []error
	setDefault := func(key string, value any) {
		if err := store.SetDefault(key, value); err != nil {
			errs = append(errs, fmt.Errorf("config: default %s: %w", key, err))
		}
	}

	// 9040, after the 9000, 9010, 9020 and 9030 of object-store,
	// secret-store, accounts and identity, so they can all run at once.
	setDefault("Server.Port", 9040)

	// The server timeouts are set here rather than left to the gas defaults
	// (5s read, 10s write), which are too short for a signed request: the
	// signature covers the whole body, so a read cut short mid-body surfaces
	// to the client as a signature failure or a broken connection rather than
	// as a timeout. A request body may be up to maxBodySize, 64 MiB, a 40 MiB
	// message base64-encoded in JSON; 60s covers that at about 9 Mbit/s,
	// far below what a local or container network carries. The largest
	// response is a message's MIME, up to 40 MiB, so writes get the same
	// budget. IdleTimeout keeps the SDKs' connection reuse working between
	// calls, and matches the gas default; it is set explicitly so it is
	// visible here rather than inherited.
	setDefault("Server.ReadTimeout", "60s")
	setDefault("Server.WriteTimeout", "60s")
	setDefault("Server.IdleTimeout", "120s")

	// The headers get 30s, well inside the whole request's budget. gas requires
	// ReadHeaderTimeout to be positive, so it cannot be unlimited even when
	// ReadTimeout is 0, and its gas default of 5s would cut a slow client's
	// headers short of the budget above.
	setDefault("Server.ReadHeaderTimeout", "30s")

	// ShutdownTimeout is shorter than the gas default of 30s, which is a
	// promise a container runtime does not keep: `docker stop` sends SIGTERM
	// and kills the process 10s later. Every request here is one SQLite
	// transaction, so in-flight work needs far less.
	//
	// It is not shorter than 7s because of a connection that was opened but
	// never sent a request, as an SDK client's spare one is. net/http closes
	// such a connection only once its whole-second timestamp is 6 seconds
	// old, 5s to 6s after it opened, and checks at most every 500ms, so the
	// shutdown can wait up to about 6.5s for it. With a shorter timeout gas
	// reports the deadline as an error and the process exits 1. Gas's
	// App.Stop returns within the timeout plus up to three 1s grace periods,
	// which only run while requests are still in flight: 10s at the very
	// worst, the edge of what docker gives.
	setDefault("Server.ShutdownTimeout", "7s")

	setDefault("Store.Path", "./data/mailbox.db")

	// Unset, mailbox runs standalone, on the root key alone.
	setDefault("Auth.IdentityEndpoint", "")

	return errors.Join(errs...)
}
