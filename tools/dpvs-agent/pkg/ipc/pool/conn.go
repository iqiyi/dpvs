// Copyright 2023 IQiYi Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pool

import (
	"bufio"
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/dpvs-agent/pkg/ipc/proto"
)

type BadConnError struct {
	wrapped error
}

var _ error = (*BadConnError)(nil)

func (e BadConnError) Error() string {
	s := "dpvs: Conn is in a bad state"
	if e.wrapped != nil {
		s += ": " + e.wrapped.Error()
	}
	return s
}

func (e BadConnError) Unwrap() error {
	return e.wrapped
}

//--------------------------------------

var noDeadline = time.Time{}

type Conn struct {
	usedAt  int64 // atomic
	netConn net.Conn

	rd *proto.Reader
	bw *bufio.Writer
	wr *proto.Writer

	Inited    bool
	pooled    bool
	createdAt time.Time
}

func NewConn(netConn net.Conn) *Conn {
	cn := &Conn{
		netConn:   netConn,
		createdAt: time.Now(),
	}
	cn.rd = proto.NewReader(netConn)
	cn.bw = bufio.NewWriter(netConn)
	cn.wr = proto.NewWriter(cn.bw)
	cn.SetUsedAt(time.Now())
	return cn
}

func (cn *Conn) UsedAt() time.Time {
	unix := atomic.LoadInt64(&cn.usedAt)
	return time.Unix(unix, 0)
}

func (cn *Conn) SetUsedAt(tm time.Time) {
	atomic.StoreInt64(&cn.usedAt, tm.Unix())
}

func (cn *Conn) SetNetConn(netConn net.Conn) {
	cn.netConn = netConn
	cn.rd.Reset(netConn)
	cn.bw.Reset(netConn)
}

/*
func (cn *Conn) Write(b []byte) (int, error) {
	offset := 0
	left := len(b)
	for left > 0 {
		written, err := cn.write(b[offset:])
		if err != nil {
			return offset, err
		}
		left -= written
		offset += written
	}
	return offset, nil
}
*/

type ConnWriteIf interface {
	Sizeof() uint64
}

func (cn *Conn) Write(o ConnWriteIf) error {
	buf := Package(o)
	_, err := cn.writeN(buf, int(o.Sizeof()))
	if err != nil {
		return err
	}
	return nil
}

func (cn *Conn) WriteN(b []byte, n int) (int, error) {
	return cn.writeN(b, n)
}

func (cn *Conn) writeN(b []byte, n int) (int, error) {
	if n > 0 && n <= len(b) {
		if err := cn.SetWriteBuffer(n); err != nil {
			return 0, err
		}
	}

	return cn.write(b)
}

/*
func (cn *Conn) Read(b []byte) (int, error) {
	offset := 0
	left := len(b)
	for left > 0 {
		readed, err := cn.read(b[offset:])
		if err != nil {
			return offset, err
		}
		offset += readed
		left -= readed
	}
	return offset, nil
}
*/

type ConnReadIf interface {
	Sizeof() uint64
	Dump([]byte) bool
}

func (cn *Conn) Read(o ConnReadIf) error {
	buf, err := cn.ReadN(int(o.Sizeof()))
	if err != nil {
		return err
	}

	o.Dump(buf)

	return nil
}

func (cn *Conn) Release(n int) {
	cn.ReadN(n)
}

func (cn *Conn) ReadN(n int) ([]byte, error) {
	return cn.readN(n)
}

func (cn *Conn) readN(n int) ([]byte, error) {
	if err := cn.SetReadBuffer(n); err != nil {
		return nil, err
	}

	b := make([]byte, n)
	readed, err := cn.read(b)
	if err != nil || readed != n {
		return nil, err
	}
	return b, nil
}

func (cn *Conn) write(b []byte) (int, error) {
	return cn.netConn.Write(b)
}

func (cn *Conn) read(b []byte) (int, error) {
	return cn.netConn.Read(b)
}

func (cn *Conn) SetWriteBuffer(bytes int) error {
	conn := cn.netConn
	if unix, ok := conn.(*net.UnixConn); ok {
		return unix.SetWriteBuffer(bytes)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		return tc.SetWriteBuffer(bytes)
	}
	if uc, ok := conn.(*net.UDPConn); ok {
		return uc.SetWriteBuffer(bytes)
	}
	if ic, ok := conn.(*net.IPConn); ok {
		return ic.SetWriteBuffer(bytes)
	}
	return nil
}

func (cn *Conn) SetReadBuffer(bytes int) error {
	conn := cn.netConn
	if unix, ok := conn.(*net.UnixConn); ok {
		return unix.SetReadBuffer(bytes)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		return tc.SetReadBuffer(bytes)
	}
	if uc, ok := conn.(*net.UDPConn); ok {
		return uc.SetReadBuffer(bytes)
	}
	if ic, ok := conn.(*net.IPConn); ok {
		return ic.SetReadBuffer(bytes)
	}
	return nil
}

func (cn *Conn) RemoteAddr() net.Addr {
	if cn.netConn != nil {
		return cn.netConn.RemoteAddr()
	}
	return nil
}

func (cn *Conn) Close() error {
	return cn.netConn.Close()
}

func (cn *Conn) deadline(ctx context.Context, timeout time.Duration) time.Time {
	tm := time.Now()
	cn.SetUsedAt(tm)

	if timeout > 0 {
		tm = tm.Add(timeout)
	}

	if ctx != nil {
		deadline, ok := ctx.Deadline()
		if ok {
			if timeout == 0 {
				return deadline
			}
			if deadline.Before(tm) {
				return deadline
			}
			return tm
		}
	}

	if timeout > 0 {
		return tm
	}

	return noDeadline
}

func (cn *Conn) WithWriter(ctx context.Context, timeout time.Duration, fn func(wr *proto.Writer) error) error {
	if err := cn.netConn.SetDeadline(cn.deadline(ctx, timeout)); err != nil {
		return err
	}

	if cn.bw.Buffered() > 0 {
		cn.bw.Reset(cn.netConn)
	}

	if err := fn(cn.wr); err != nil {
		return err
	}

	if err := cn.bw.Flush(); err != nil {
		return err
	}

	return nil
	/*
	   return internal.WithSpan(ctx, "dpvs-agent.with_writer", func(ctx context.Context, span trace.Span) error {
	       if err := cn.netConn.SetWriteDeadline(cn.deadline(ctx, timeout)); err != nil {
	           return internal.RecordError(ctx, span, err)
	       }

	       if cn.bw.Buffered() > 0 {
	           cn.bw.Reset(cn.netConn)
	       }

	       if err := fn(cn.wr); err != nil {
	           return internal.RecordError(ctx, span, err)
	       }

	       if err := cn.bw.Flush(); err != nil {
	           return internal.RecordError(ctx, span, err)
	       }

	       internal.WritesCounter.Add(ctx, 1)

	       return nil
	   })
	*/
}

func (cn *Conn) WithReader(ctx context.Context, timeout time.Duration, fn func(rd *proto.Reader) error) error {
	if err := cn.netConn.SetDeadline(cn.deadline(ctx, timeout)); err != nil {
		return err
	}

	if err := fn(cn.rd); err != nil {
		return err
	}

	return nil
	/*
	   return internal.WithSpan(ctx, "dpvs-agent.with_reader", func(ctx context.Context, span trace.Span) error {
	       if err := cn.netConn.SetReadDeadline(cn.deadline(ctx, timeout)); err != nil {
	           return internal.RecordError(ctx, span, err)
	       }
	       if err := fn(cn.rd); err != nil {
	           return internal.RecordError(ctx, span, err)
	       }
	       return nil
	   })
	*/
}
