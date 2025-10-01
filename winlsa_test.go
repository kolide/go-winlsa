//go:build windows
// +build windows

package winlsa

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetLogonSessions_GetLogonSessionData(t *testing.T) {
	t.Parallel()

	luids, err := GetLogonSessions()
	require.NoError(t, err)

	for _, luid := range luids {
		sessionData, err := GetLogonSessionData(&luid)
		require.NoError(t, err)
		require.NotNil(t, sessionData.Sid)
	}
}
