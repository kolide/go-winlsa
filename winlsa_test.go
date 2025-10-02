//go:build windows
// +build windows

package winlsa

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetLogonSessions_GetLogonSessionData(t *testing.T) {
	t.Parallel()

	luids, err := GetLogonSessions()
	require.NoError(t, err, "getting logon sessions")

	for _, luid := range luids {
		sessionData, err := GetLogonSessionData(&luid)
		require.NoError(t, err, "getting logon session data")
		require.Greater(t, sessionData.LogonTime.Unix(), int64(0), "logon time not set in session data", fmt.Sprintf("%+v", sessionData))
	}
}
