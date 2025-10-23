package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/Nativu5/terasu-proxy/internal/tls"
	"github.com/Nativu5/terasu-proxy/internal/utils"
)

// Server implements the transparent TLS proxy with ClientHello record splitting.
type Server struct {
	config utils.Config
	log    *logrus.Entry
	dialer *net.Dialer
	gapMin time.Duration
	gapMax time.Duration
}

// NewServer builds a Server using the provided configuration and logger.
func NewServer(config utils.Config, logger *logrus.Entry) *Server {
	if logger == nil {
		logger = logrus.NewEntry(logrus.StandardLogger())
	}

	dialer := &net.Dialer{
		Timeout: config.DialTimeout,
		Control: func(_, _ string, c syscall.RawConn) error {
			if config.Mark == 0 {
				return nil
			}
			var ctrlErr error
			if err := c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, config.Mark); err != nil {
					ctrlErr = fmt.Errorf("set SO_MARK: %w", err)
				}
			}); err != nil {
				return err
			}
			return ctrlErr
		},
	}

	return &Server{
		config: config,
		log:    logger.WithField("component", "server"),
		dialer: dialer,
		gapMin: config.GapMin,
		gapMax: config.GapMax,
	}
}

// Run starts listening and processing connections until the context is cancelled or a fatal error occurs.
func (s *Server) Run(ctx context.Context) error {
	listener, err := newTransparentListener(ctx, s.config, s.log)
	if err != nil {
		return err
	}
	defer listener.Close()

	s.log.Infof("transparent proxy listening at %s", s.config.ListenAddr)

	var wg sync.WaitGroup
	defer wg.Wait()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		client, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				s.log.WithError(err).Warn("accept timeout")
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}

		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			s.handleConn(ctx, conn)
		}(client)
	}
}

func (s *Server) handleConn(ctx context.Context, client net.Conn) {
	defer client.Close()

	origDst := client.LocalAddr().String()
	peer := client.RemoteAddr().String()
	connLog := s.log.WithFields(logrus.Fields{
		"peer": peer,
		"dst":  origDst,
	})
	connLog.Info("accepted connection")

	dialCtx, cancel := context.WithTimeout(ctx, s.config.DialTimeout)
	defer cancel()

	upstream, err := s.dialer.DialContext(dialCtx, "tcp", origDst)
	if err != nil {
		connLog.WithError(err).Warn("dial upstream failed")
		return
	}
	defer upstream.Close()

	if tcp, ok := upstream.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	stopCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
			_ = upstream.Close()
		case <-stopCh:
		}
	}()
	defer close(stopCh)

	record, rawBytes, err := tls.ReadInitialRecord(client, s.config.ReadTimeout, s.config.MaxRecordSize)
	if err != nil {
		if len(rawBytes) > 0 {
			if _, writeErr := upstream.Write(rawBytes); writeErr != nil {
				connLog.WithError(writeErr).Warn("forward partial data to upstream failed")
				return
			}
		}
		connLog.WithError(err).Debug("falling back to transparent piping after read failure")
		pipe(connLog, client, upstream)
		return
	}

	records, err := record.SplitClientHello(s.config.FirstFragment)
	if err != nil {
		if errors.Is(err, tls.ErrNotHandshake) || errors.Is(err, tls.ErrNotClientHello) {
			connLog.Debug("first record not ClientHello handshake; forwarding transparently")
		} else {
			connLog.WithError(err).Warn("unable to split ClientHello; forwarding transparently")
		}
		if len(rawBytes) > 0 {
			if _, writeErr := upstream.Write(rawBytes); writeErr != nil {
				connLog.WithError(writeErr).Warn("forward initial record upstream failed")
				return
			}
		}
		pipe(connLog, client, upstream)
		return
	}

	if err := tls.WriteRecords(upstream, records, s.gapMin, s.gapMax); err != nil {
		connLog.WithError(err).Warn("writing split records failed")
		return
	}
	if len(records) > 1 {
		connLog.Debug("successfully split ClientHello record")
	} else {
		connLog.Debug("forwarded ClientHello without splitting (first fragment disabled)")
	}

	pipe(connLog, client, upstream)
}
