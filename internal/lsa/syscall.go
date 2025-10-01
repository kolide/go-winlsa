//go:build windows
// +build windows

package lsa

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	secur32                       = windows.NewLazySystemDLL("Secur32.dll")
	advapi32                      = windows.NewLazySystemDLL("Advapi32.dll")
	procLsaEnumerateLogonSessions = secur32.NewProc("LsaEnumerateLogonSessions")
	procLsaGetLogonSessionData    = secur32.NewProc("LsaGetLogonSessionData")
	procLsaFreeReturnBuffer       = secur32.NewProc("LsaFreeReturnBuffer")
	procLsaNtStatusToWinError     = advapi32.NewProc("LsaNtStatusToWinError")
)

func LsaEnumerateLogonSessions(sessionCount *uint32, sessions *uintptr) error {
	r0, _, _ := syscall.SyscallN(procLsaEnumerateLogonSessions.Addr(), uintptr(unsafe.Pointer(sessionCount)), uintptr(unsafe.Pointer(sessions)))
	return LsaNtStatusToWinError(r0)
}
func LsaGetLogonSessionData(luid *LUID, sessionData **SECURITY_LOGON_SESSION_DATA) error {
	r0, _, _ := syscall.SyscallN(procLsaGetLogonSessionData.Addr(), uintptr(unsafe.Pointer(luid)), uintptr(unsafe.Pointer(sessionData)))
	return LsaNtStatusToWinError(r0)
}
func LsaFreeReturnBuffer(buffer uintptr) error {
	r0, _, _ := syscall.SyscallN(procLsaFreeReturnBuffer.Addr(), buffer)
	return LsaNtStatusToWinError(r0)
}
func LsaNtStatusToWinError(ntstatus uintptr) error {
	r0, _, errno := syscall.SyscallN(procLsaNtStatusToWinError.Addr(), 1, ntstatus)
	switch errno { // nolint:exhaustive
	case windows.ERROR_SUCCESS:
		if r0 == 0 {
			return nil
		}
	case windows.ERROR_MR_MID_NOT_FOUND:
		return fmt.Errorf("Unknown LSA NTSTATUS code %x", ntstatus)
	}
	return syscall.Errno(r0)
}
