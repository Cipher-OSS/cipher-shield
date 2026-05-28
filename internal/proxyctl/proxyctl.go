package proxyctl

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// ConfigDir returns ~/.cipher-shield/
func ConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cipher-shield")
}

func pidFile() string    { return filepath.Join(ConfigDir(), "proxy.pid") }
func origNPMFile() string { return filepath.Join(ConfigDir(), "npm_registry.orig") }
func origPIPFile() string { return filepath.Join(ConfigDir(), "pip_index.orig") }

// SaveAndSetNPM saves the current npm registry and points npm at the proxy.
func SaveAndSetNPM(proxyAddr string) error {
	out, _ := exec.Command("npm", "config", "get", "registry").Output()
	orig := strings.TrimSpace(string(out))
	if orig == "" {
		orig = "https://registry.npmjs.org/"
	}
	if err := os.MkdirAll(ConfigDir(), 0700); err != nil {
		return err
	}
	os.WriteFile(origNPMFile(), []byte(orig), 0600)
	return exec.Command("npm", "config", "set", "registry", proxyAddr).Run()
}

// RestoreNPM restores the original npm registry.
func RestoreNPM() {
	data, err := os.ReadFile(origNPMFile())
	if err != nil {
		return
	}
	orig := strings.TrimSpace(string(data))
	if orig != "" {
		exec.Command("npm", "config", "set", "registry", orig).Run()
	}
	os.Remove(origNPMFile())
}

// SaveAndSetPIP saves the current pip index URL and points pip at the proxy.
// Writes ~/.pip/pip.conf (macOS/Linux) or %APPDATA%\pip\pip.ini (Windows).
func SaveAndSetPIP(proxyAddr string) error {
	pipConf := pipConfigPath()

	existing, _ := os.ReadFile(pipConf)
	origURL := ""
	for _, line := range strings.Split(string(existing), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "index-url") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				origURL = strings.TrimSpace(parts[1])
			}
		}
	}
	if origURL == "" {
		origURL = "https://pypi.org/simple/"
	}

	if err := os.MkdirAll(ConfigDir(), 0700); err != nil {
		return err
	}
	os.WriteFile(origPIPFile(), []byte(origURL), 0600)

	os.MkdirAll(filepath.Dir(pipConf), 0700)
	conf := fmt.Sprintf("[global]\nindex-url = %s/simple/\n", proxyAddr)
	return os.WriteFile(pipConf, []byte(conf), 0600)
}

// RestorePIP restores the original pip index URL.
func RestorePIP() {
	pipConf := pipConfigPath()
	data, err := os.ReadFile(origPIPFile())
	if err != nil {
		os.Remove(pipConf)
		return
	}
	orig := strings.TrimSpace(string(data))
	if orig == "" || orig == "https://pypi.org/simple/" {
		os.Remove(pipConf)
	} else {
		conf := fmt.Sprintf("[global]\nindex-url = %s\n", orig)
		os.WriteFile(pipConf, []byte(conf), 0600)
	}
	os.Remove(origPIPFile())
}

func pipConfigPath() string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "windows" {
		appdata := os.Getenv("APPDATA")
		return filepath.Join(appdata, "pip", "pip.ini")
	}
	return filepath.Join(home, ".pip", "pip.conf")
}

// WritePID writes the given PID to the pid file.
func WritePID(pid int) error {
	if err := os.MkdirAll(ConfigDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(pidFile(), []byte(strconv.Itoa(pid)), 0600)
}

// ReadPID reads the PID from the pid file. Returns 0 if not found.
func ReadPID() int {
	data, err := os.ReadFile(pidFile())
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return pid
}

// RemovePID removes the pid file.
func RemovePID() { os.Remove(pidFile()) }

// IsRunning returns true if the proxy process is running.
func IsRunning() bool {
	pid := ReadPID()
	if pid == 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		// On Windows, FindProcess always succeeds for any PID; assume running.
		return true
	}
	// On Unix, send signal 0 to check if the process is alive.
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}

// Status returns a human-readable status string.
func Status() string {
	pid := ReadPID()
	if pid == 0 {
		return "stopped"
	}
	if IsRunning() {
		return fmt.Sprintf("running (pid %d)", pid)
	}
	return "stopped (stale pid file)"
}
