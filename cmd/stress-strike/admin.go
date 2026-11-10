package main

// cmdAdmin implements `stress-strike admin` — the local maintenance switch.
//
// The admin area is deliberately boring and local:
//
//	stress-strike admin            show the status and the code
//	stress-strike admin code       print the code (for the dashboard panel)
//	stress-strike admin status     show the current bypass window
//	stress-strike admin rotate     mint a new code (the "code leaked" step)
//	stress-strike admin lock       close the window immediately
//	stress-strike admin unlock     open the window for --minutes (default 15)
//
// An open window makes every authorization gate on this host allow work
// without an authorization ticket. It expires, it is audit-logged, and it
// never unlocks cloud instance metadata.

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/adminlock"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
)

func cmdAdmin() {
	args := os.Args[2:]
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
		args = args[1:]
	}

	switch sub {
	case "code":
		adminCode()
	case "status", "show":
		adminStatus()
	case "rotate", "new":
		adminRotate()
	case "unlock", "on":
		adminUnlock(args)
	case "lock", "off":
		adminLock()
	case "help", "--help", "-h":
		adminUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown admin subcommand %q\n\n", sub)
		adminUsage()
		exitProcess(2)
	}
}

func adminUsage() {
	fmt.Fprint(os.Stderr, `usage: stress-strike admin [code|status|rotate|unlock|lock]

The admin code and the bypass window live in `+adminlock.DefaultPath()+`.

  code            print the admin code
  status          show whether the bypass window is open and for how long
  rotate          issue a new code and close the window
  unlock          open the window (--code CODE, --minutes N; default 15 min)
  lock            close the window now

An open window lets scans run without an authorization ticket on this host.
It expires automatically, is written to the audit log, and never unlocks cloud
instance-metadata addresses. The dashboard panel is hidden behind the admin
code and shows the same state.
`)
}

func adminStore() *adminlock.Store {
	s, err := adminlock.Open(adminlock.DefaultPath())
	if err != nil {
		fatal(fmt.Errorf("open admin state: %w", err))
	}
	return s
}

func adminCode() {
	s := adminStore()
	code, err := s.Code()
	if err != nil {
		fatal(err)
	}
	fmt.Println(code)
}

func adminStatus() {
	s := adminStore()
	code, err := s.Code()
	if err != nil {
		fatal(err)
	}
	st, err := s.Status()
	if err != nil {
		fatal(err)
	}
	fmt.Println("Admin area")
	fmt.Printf("  code file   %s\n", s.Path())
	fmt.Printf("  code        %s\n", code)
	if st.Active {
		fmt.Printf("  bypass      ON — %s left (until %s)\n",
			humanSeconds(st.SecondsLeft), st.ExpiresAt.Local().Format("2006-01-02 15:04:05"))
		fmt.Println("  effect      scans run WITHOUT an authorization ticket")
	} else {
		fmt.Println("  bypass      off — authorization is enforced normally")
	}
	fmt.Println()
	fmt.Println("Reveal the dashboard panel: Ctrl+Shift+A, or click the logo 5 times, or open /#admin")
	fmt.Println("Then enter the code above to switch the bypass on or off.")
}

func adminRotate() {
	s := adminStore()
	code, err := s.Rotate()
	if err != nil {
		fatal(err)
	}
	fmt.Printf("New admin code: %s\n", code)
	fmt.Println("The previous code no longer works and any open bypass window is closed.")
}

func adminUnlock(args []string) {
	fs := flag.NewFlagSet("admin unlock", flag.ContinueOnError)
	code := fs.String("code", "", "admin code (default: prompt, or STRESS_STRIKE_ADMIN_CODE)")
	minutes := fs.Int("minutes", 15, "how long the bypass stays open (1–1440)")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	s := adminStore()
	c := strings.TrimSpace(*code)
	if c == "" {
		c = strings.TrimSpace(os.Getenv("STRESS_STRIKE_ADMIN_CODE"))
	}
	if c == "" {
		fmt.Print("Admin code: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		c = strings.TrimSpace(line)
	}
	if c == "" {
		fatal(fmt.Errorf("no admin code given — run `stress-strike admin code` on this host to read it"))
	}

	ttl := time.Duration(*minutes) * time.Minute
	st, err := s.Unlock(c, ttl)
	if err != nil {
		fatal(err)
	}

	recordAdminEvent("admin-unlock", true, "bypass window opened for "+humanSeconds(st.SecondsLeft))
	fmt.Println("Admin bypass is ON")
	fmt.Printf("  expires in  %s (at %s)\n", humanSeconds(st.SecondsLeft), st.ExpiresAt.Local().Format("2006-01-02 15:04:05"))
	fmt.Println("  effect      scans run WITHOUT an authorization ticket")
	fmt.Println("  still off   cloud instance metadata (169.254.169.254) stays denied")
	fmt.Println()
	fmt.Println("Turn it off now:  stress-strike admin lock")
}

func adminLock() {
	s := adminStore()
	st, err := s.Lock()
	if err != nil {
		fatal(err)
	}
	recordAdminEvent("admin-lock", true, "bypass window closed")
	fmt.Println("Admin bypass is OFF — authorization is enforced normally.")
	if st.Active {
		fmt.Fprintf(os.Stderr, "warning: window still reports active for %s; check %s\n", humanSeconds(st.SecondsLeft), s.Path())
	}
}

// recordAdminEvent writes the switch change to the same hash-chained trail as
// scans, so `stress-strike audit show` explains why a scan had no ticket.
func recordAdminEvent(rule string, allowed bool, reason string) {
	recordAuthz(authz.Entry{
		Actor:   "local-admin",
		Action:  "admin",
		Targets: []string{"local"},
		Class:   "local",
		Allowed: allowed,
		Rule:    rule,
		Reason:  reason,
		Version: buildVersion,
		Argv:    os.Args,
	}, "", "")
}

func humanSeconds(sec int64) string {
	if sec <= 0 {
		return "0s"
	}
	if sec < 60 {
		return fmt.Sprintf("%ds", sec)
	}
	m := sec / 60
	s := sec % 60
	if s == 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%dm %ds", m, s)
}
