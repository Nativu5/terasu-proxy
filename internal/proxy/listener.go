package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/sirupsen/logrus"

	"github.com/Nativu5/terasu-proxy/internal/utils"
)

func newTransparentListener(ctx context.Context, config utils.Config, logger *logrus.Entry) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var setupErr error
			if err := c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					setupErr = fmt.Errorf("set SO_REUSEADDR: %w", err)
					return
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
					setupErr = fmt.Errorf("set IP_TRANSPARENT: %w", err)
					return
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil && !errors.Is(err, unix.ENOPROTOOPT) && !errors.Is(err, unix.EINVAL) {
					logger.WithError(err).Debug("set SO_REUSEPORT failed")
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil && !errors.Is(err, unix.ENOPROTOOPT) && !errors.Is(err, unix.EINVAL) {
					logger.WithError(err).Debug("set IPV6_TRANSPARENT failed")
				}
			}); err != nil {
				return err
			}
			return setupErr
		},
	}

	listener, err := lc.Listen(ctx, "tcp", config.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s/%s: %w", "tcp", config.ListenAddr, err)
	}
	return listener, nil
}
