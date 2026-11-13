// Command tule-mailbox serves an Amazon SES v2-compatible API that stores
// every message it accepts in a local SQLite database instead of delivering
// it, and a retrieval API to read the stored messages back.
package main

import (
	"context"
	"fmt"
	"log"

	"tule.dev/mailbox/internal/app"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() (err error) {
	cfg, cfgErr := app.LoadConfig()
	if cfgErr != nil {
		return fmt.Errorf("failed to load config: %w", cfgErr)
	}

	a, appErr := app.New(cfg)
	if appErr != nil {
		return fmt.Errorf("failed to create application: %w", appErr)
	}

	if runErr := a.Run(context.Background()); runErr != nil {
		return fmt.Errorf("app exited with error: %w", runErr)
	}

	return
}
