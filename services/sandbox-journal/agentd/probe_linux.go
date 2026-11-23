package agentd

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// linuxProcessIdentity uses the real kernel process identity, not kill(pid,0)
// alone: PID may have been recycled after AgentD/Worker SIGKILL. Absence
// cannot distinguish successful exit, crash, or a previously completed effect.
func linuxProcessIdentity(pid int) (string, uint64, bool, error) {
	if pid <= 0 {
		return "", 0, false, ErrUnverified
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", 0, false, err
	}
	bootID := strings.TrimSpace(string(boot))
	if !bootIDRef.MatchString(bootID) {
		return "", 0, false, ErrUnverified
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", 0, false, err
	}
	// Linux /proc/pid/stat field 2 (comm) is enclosed in parentheses
	// and may itself contain spaces or parentheses. Starttime is field 22,
	// i.e. offset 19 after splitting the suffix beginning with field 3.
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 || end+1 >= len(stat) {
		return "", 0, false, ErrUnverified
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return "", 0, false, ErrUnverified
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 {
		return "", 0, false, ErrUnverified
	}
	alive := fields[0] != "Z" && fields[0] != "X" && fields[0] != "x"
	return bootID, ticks, alive, nil
}

// CaptureLinuxProcessIdentity is only a source-side helper for a process the
// supervisor *already started with an authorized Permit*. This code does not
// provide a start/dispatch API or treat process observation as authorization.
func CaptureLinuxProcessIdentity(pid int) (string, uint64, error) {
	boot, ticks, alive, err := linuxProcessIdentity(pid)
	if err != nil {
		return "", 0, err
	}
	if !alive {
		return "", 0, errors.New("original OS process is not running")
	}
	return boot, ticks, nil
}

// inspectLinuxOriginalProcess returns diagnostic liveness only. No result
// other than the persisted signed Wait receipt can promote UNKNOWN to EXITED.
func inspectLinuxOriginalProcess(r Ref) string {
	boot, ticks, alive, err := linuxProcessIdentity(r.ProcessPID)
	if err != nil || !alive || boot != r.HostBootID || ticks != r.ProcessStartTicks {
		return "ABSENT_REUSED_OR_UNVERIFIED"
	}
	return "ALIVE_ORIGINAL_PROCESS"
}
