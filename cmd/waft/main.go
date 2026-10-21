// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

// Command waft sends end-to-end encrypted pushes and files to your Waft devices.
//
//	export WAFT_SERVER=https://push.example.com
//	export WAFT_TOKEN=gpt_...        # Settings > API tokens in the web app
//	export WAFT_KEY='your E2EE passphrase'
//
//	waft "Build finished"                       # push to all devices
//	waft -to pixel-7 -t "Deploy" "v2.4.1 live"  # push to one device
//	echo hello | waft                           # body from stdin
//	waft -file ./report.pdf                     # encrypted resumable upload
//	waft -devices                               # list devices
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hj91/waft/pkg/client"
	"github.com/hj91/waft/pkg/e2ee"
)

func main() {
	host, _ := os.Hostname()
	server := flag.String("server", envOr("WAFT_SERVER", "http://localhost:8080"), "Waft server URL (WAFT_SERVER)")
	token := flag.String("token", "", "API token; prefer WAFT_TOKEN or -token-file")
	tokenFile := flag.String("token-file", "", "File containing the API token")
	key := flag.String("key", "", "E2EE passphrase; prefer WAFT_KEY or -key-file")
	keyFile := flag.String("key-file", "", "File containing the E2EE passphrase")
	target := flag.String("to", "*", "Target device_id, or * for all devices")
	title := flag.String("t", "", "Push title")
	link := flag.String("url", "", "Optional URL to attach")
	source := flag.String("from", envOr("WAFT_DEVICE", "cli-"+sanitize(host)), "Source device_id (WAFT_DEVICE)")
	filePath := flag.String("file", "", "Upload this file (encrypted, resumable)")
	listDevices := flag.Bool("devices", false, "List your devices and exit")
	flag.Parse()

	tok, err := client.ResolveSecret(*token, *tokenFile, "WAFT_TOKEN")
	fail(err)
	c, err := client.New(*server, tok)
	fail(err)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *listDevices {
		devs, err := c.Devices(ctx)
		fail(err)
		for _, d := range devs {
			state := "offline"
			if d.Online {
				state = "online"
			}
			fmt.Printf("%-28s %-8s %-14s %s\n", d.DeviceID, state, d.Platform, d.Nickname)
		}
		return
	}

	pass, err := client.ResolveSecret(*key, *keyFile, "WAFT_KEY")
	fail(err)
	if pass == "" {
		fail(fmt.Errorf("E2EE passphrase required (WAFT_KEY, -key-file or -key)"))
	}
	k, _, err := c.DeriveKey(ctx, pass)
	fail(err)

	if *filePath != "" {
		start := time.Now()
		err := c.UploadFile(ctx, k, *filePath, *source, *target, func(done, total int64) {
			fmt.Fprintf(os.Stderr, "\rUploaded %d / %d bytes (%.1f%%)", done, total, float64(done)*100/float64(total))
		})
		fmt.Fprintln(os.Stderr)
		fail(err)
		fmt.Printf("File sent and verified in %s\n", time.Since(start).Round(time.Millisecond))
		return
	}

	body := strings.Join(flag.Args(), " ")
	if body == "" {
		if stat, _ := os.Stdin.Stat(); stat != nil && stat.Mode()&os.ModeCharDevice == 0 {
			b, _ := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
			body = strings.TrimSpace(string(b))
		}
	}
	if body == "" && *link == "" {
		fmt.Fprintln(os.Stderr, "Usage: waft [-to device] [-t title] [-url link] <message>  |  waft -file path  |  waft -devices")
		os.Exit(2)
	}
	t := *title
	if t == "" {
		t = "Push from " + *source
	}
	env, err := c.Push(ctx, k, "push", *source, *target, e2ee.SecretPayload{Title: t, Body: body, URL: *link})
	fail(err)
	fmt.Printf("Sent encrypted push #%d to %s\n", env.SeqID, env.TargetDevice)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_' {
			return r
		}
		return '-'
	}, s)
	if len(s) > 56 {
		s = s[:56]
	}
	return s
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "waft:", err)
		os.Exit(1)
	}
}
