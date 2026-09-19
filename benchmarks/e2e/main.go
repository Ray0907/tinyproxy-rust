// End-to-end loopback load generator. It is test tooling, not proxy runtime code.
package main

import (
    "bufio"
    "bytes"
    "context"
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/url"
    "os"
    "sort"
    "strconv"
    "sync"
    "sync/atomic"
    "time"

    "golang.org/x/net/http2"
)

var (
    mode = flag.String("mode", "load", "origin or load")
    kind = flag.String("kind", "http", "http, tunnel, or idle")
    protocol = flag.String("protocol", "h1", "h1, h1tls, h2c, h2tls")
    proxy = flag.String("proxy", "", "proxy host:port; empty means direct")
    target = flag.String("target", "127.0.0.1:18080", "origin or echo host:port")
    ca = flag.String("ca", "", "trusted test CA PEM")
    concurrency = flag.Int("c", 32, "parallel workers / held tunnels")
    connections = flag.Int("connections", 1, "exact HTTP/2 connections")
    size = flag.Int("size", 1024, "response / echo bytes")
    method = flag.String("method", "GET", "HTTP method")
    fresh = flag.Bool("fresh", false, "disable HTTP/1 connection reuse")
    duration = flag.Duration("duration", 5*time.Second, "measurement admission window")
    warmup = flag.Duration("warmup", time.Second, "unmeasured warmup")
    hold = flag.Duration("hold", 6*time.Second, "idle tunnel hold time")
)

func emit(v any) { if err := json.NewEncoder(os.Stdout).Encode(v); err != nil { panic(err) } }
func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
func main() {
    flag.Parse()
    if *mode == "origin" { if err := serveOrigin(); err != nil { fail(err) }; return }
    if *concurrency < 1 || *concurrency > 2048 || *size < 1 || *size > 8<<20 || *connections < 1 { fail(fmt.Errorf("invalid bounds")) }
    if err := run(); err != nil { fail(err) }
}

func serveOrigin() error {
    echo, err := net.Listen("tcp", "127.0.0.1:18081"); if err != nil { return err }
    go func() { for { c, e := echo.Accept(); if e != nil { return }; go func() { defer c.Close(); _, _ = io.Copy(c, c) }() } }()
    payload := bytes.Repeat([]byte("x"), 8<<20)
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        n, e := strconv.Atoi(r.URL.Query().Get("size")); if e != nil || n < 1 || n > len(payload) { http.Error(w,"size",400); return }
        if r.Header.Get("Proxy-Authorization") != "" { http.Error(w,"credential leak",500); return }
        if r.Method == "POST" {
            b, e := io.ReadAll(io.LimitReader(r.Body, int64(n)+1)); _ = r.Body.Close()
            if e != nil || !bytes.Equal(b, payload[:n]) { http.Error(w,"bad upload",400); return }
        }
        w.Header().Set("Content-Type", "application/octet-stream")
        w.Header().Set("Content-Length", strconv.Itoa(n))
        _, _ = w.Write(payload[:n])
    })
    server := &http.Server{Addr:"127.0.0.1:18080", Handler:handler, ReadHeaderTimeout:5*time.Second, IdleTimeout:30*time.Second}
    emit(map[string]any{"ready":true, "http":server.Addr, "echo":"127.0.0.1:18081"})
    return server.ListenAndServe()
}

type clients struct {
    h1 *http.Transport
    h2 []*http2.ClientConn
    tlsConfig *tls.Config
    dials atomic.Int64
}
func newClients() (*clients, error) {
    c := &clients{}
    if *protocol == "h1tls" || *protocol == "h2tls" {
        cert, err := os.ReadFile(*ca); if err != nil { return nil, err }
        roots := x509.NewCertPool(); if !roots.AppendCertsFromPEM(cert) { return nil, fmt.Errorf("invalid test CA") }
        alpn := "http/1.1"; if *protocol == "h2tls" { alpn = "h2" }
        c.tlsConfig = &tls.Config{RootCAs:roots, ServerName:"localhost", NextProtos:[]string{alpn}, MinVersion:tls.VersionTLS12}
    }
    if *protocol == "h2c" || *protocol == "h2tls" {
        if *proxy == "" { return nil, fmt.Errorf("h2 requires proxy address") }
        tr := &http2.Transport{AllowHTTP:true}
        for i:=0; i<*connections; i++ {
            conn, err := c.dial(); if err != nil { c.close(); return nil, err }
            cc, err := tr.NewClientConn(conn); if err != nil { conn.Close(); c.close(); return nil, err }
            c.h2 = append(c.h2, cc)
            ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
            err = cc.Ping(ctx); cancel(); if err != nil { c.close(); return nil, err }
        }
    } else {
        dialer := &net.Dialer{Timeout:5*time.Second, KeepAlive:30*time.Second}
        c.h1 = &http.Transport{
            Proxy:nil, DisableKeepAlives:*fresh, DisableCompression:true,
            MaxIdleConns:*concurrency, MaxIdleConnsPerHost:*concurrency, MaxConnsPerHost:*concurrency,
            IdleConnTimeout:15*time.Second, TLSHandshakeTimeout:5*time.Second, ResponseHeaderTimeout:10*time.Second,
            ForceAttemptHTTP2:false, TLSNextProto:make(map[string]func(string,*tls.Conn) http.RoundTripper), TLSClientConfig:c.tlsConfig,
            DialContext:func(ctx context.Context, network, addr string)(net.Conn,error) {
                conn, err := dialer.DialContext(ctx, network, addr); if err == nil { c.dials.Add(1) }; return conn,err
            },
        }
        if *proxy != "" {
            scheme := "http"; if *protocol == "h1tls" { scheme = "https" }
            u, err := url.Parse(scheme+"://"+*proxy); if err != nil { return nil, err }; c.h1.Proxy = http.ProxyURL(u)
        }
    }
    return c, nil
}
func (c *clients) dial() (net.Conn,error) {
    addr := *proxy; if addr == "" { addr = *target }
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second); defer cancel()
    conn, err := (&net.Dialer{}).DialContext(ctx,"tcp",addr); if err != nil { return nil,err }
    c.dials.Add(1)
    if c.tlsConfig != nil {
        secure := tls.Client(conn,c.tlsConfig)
        if err = secure.HandshakeContext(ctx); err != nil { conn.Close(); return nil,err }
        if *protocol == "h2tls" && secure.ConnectionState().NegotiatedProtocol != "h2" { secure.Close(); return nil,fmt.Errorf("h2 ALPN not negotiated") }
        return secure,nil
    }
    return conn,nil
}
func (c *clients) close() { if c.h1 != nil { c.h1.CloseIdleConnections() }; for _, cc := range c.h2 { _ = cc.Close() } }
func (c *clients) request(worker int, payload, received []byte) (int,error) {
    ctx,cancel := context.WithTimeout(context.Background(),10*time.Second); defer cancel()
    var body io.Reader
    if *method == "POST" { body = bytes.NewReader(payload) }
    req,err := http.NewRequestWithContext(ctx,*method,"http://"+*target+"/data?size="+strconv.Itoa(*size),body)
    if err != nil { return 0,err }
    var resp *http.Response
    if c.h1 != nil { resp,err=c.h1.RoundTrip(req) } else { resp,err=c.h2[worker%len(c.h2)].RoundTrip(req) }
    if err != nil { return 0,err }; defer resp.Body.Close()
    if resp.StatusCode != 200 { return resp.ProtoMajor, fmt.Errorf("HTTP status %d",resp.StatusCode) }
    if len(c.h2)>0 && resp.ProtoMajor != 2 { return resp.ProtoMajor,fmt.Errorf("expected HTTP/2, got %s",resp.Proto) }
    if _,err=io.ReadFull(resp.Body, received); err != nil { return resp.ProtoMajor,err }
    var extra [1]byte
    n,err:=resp.Body.Read(extra[:]); if n!=0 || err!=io.EOF { return resp.ProtoMajor,fmt.Errorf("unexpected body end: n=%d err=%v",n,err) }
    if !bytes.Equal(payload,received) { return resp.ProtoMajor,fmt.Errorf("body mismatch") }
    return resp.ProtoMajor,nil
}

type tunnel struct { r io.Reader; w io.Writer; closeFn func(); once sync.Once }
func (t *tunnel) close() { t.once.Do(t.closeFn) }
func (c *clients) openTunnel(worker int) (*tunnel,error) {
    if len(c.h2)>0 {
        pr,pw := io.Pipe()
        ctx,cancel:=context.WithCancel(context.Background())
        req:=(&http.Request{Method:"CONNECT",URL:&url.URL{Scheme:"http",Host:*target},Host:*target,Header:make(http.Header),Body:pr,ContentLength:-1}).WithContext(ctx)
        timer:=time.AfterFunc(10*time.Second,cancel)
        resp,err:=c.h2[worker%len(c.h2)].RoundTrip(req); timer.Stop()
        if err!=nil { cancel();pr.Close();pw.Close();return nil,err }
        if resp.StatusCode!=200 { cancel();resp.Body.Close();pr.Close();pw.Close();return nil,fmt.Errorf("CONNECT status %d",resp.StatusCode) }
        return &tunnel{r:resp.Body,w:pw,closeFn:func(){cancel();_ = pw.Close();_ = pr.Close();_ = resp.Body.Close()}},nil
    }
    conn,err:=c.dial();if err!=nil{return nil,err}
    if *proxy==""{return &tunnel{r:conn,w:conn,closeFn:func(){conn.Close()}},nil}
    _ = conn.SetDeadline(time.Now().Add(10*time.Second))
    if _,err=fmt.Fprintf(conn,"CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",*target,*target);err!=nil{conn.Close();return nil,err}
    reader:=bufio.NewReader(conn)
    resp,err:=http.ReadResponse(reader,&http.Request{Method:"CONNECT"})
    if err!=nil{conn.Close();return nil,err}
    if resp.StatusCode!=200{resp.Body.Close();conn.Close();return nil,fmt.Errorf("CONNECT status %d",resp.StatusCode)}
    _ = conn.SetDeadline(time.Time{})
    return &tunnel{r:reader,w:conn,closeFn:func(){conn.Close()}},nil
}
func (t *tunnel) exchange(payload, received []byte) error {
    timer:=time.AfterFunc(10*time.Second,t.close);defer timer.Stop()
    written:=make(chan error,1)
    go func(){_,err:=io.Copy(t.w,bytes.NewReader(payload));written<-err}()
    _,err:=io.ReadFull(t.r,received)
    if err!=nil{t.close();<-written;return err}
    if err=<-written;err!=nil{return err}
    if !bytes.Equal(payload,received){return fmt.Errorf("tunnel body mismatch")}
    return nil
}

type result struct {
    Success int `json:"success"`
    Errors int `json:"errors"`
    ErrorSamples []string `json:"error_samples"`
    Seconds float64 `json:"seconds"`
    RequestsPerSecond float64 `json:"rps"`
    MiBPerSecond float64 `json:"mib_s"`
    P50 float64 `json:"p50_ms"`
    P95 float64 `json:"p95_ms"`
    P99 float64 `json:"p99_ms"`
    Dials int64 `json:"tcp_dials_including_warmup"`
    Protocol string `json:"protocol"`
    Concurrency int `json:"concurrency"`
    BodyBytes int `json:"body_bytes"`
    WarmupSuccess int `json:"warmup_success"`
    WarmupErrors int `json:"warmup_errors"`
}
func run() error {
    c,err:=newClients();if err!=nil{return err};defer c.close()
    tunnels:=make([]*tunnel,*concurrency)
    if *kind!="http"{
        var wg sync.WaitGroup;var mu sync.Mutex;var errs []string
        for i:=range tunnels{wg.Add(1);go func(i int){defer wg.Done();t,e:=c.openTunnel(i);mu.Lock();defer mu.Unlock();if e!=nil{errs=append(errs,e.Error())}else{tunnels[i]=t}}(i)}
        wg.Wait()
        defer func(){for _,t:=range tunnels{if t!=nil{t.close()}}}()
        if *kind=="idle"{emit(map[string]any{"ready_idle":*concurrency-len(errs),"errors":len(errs),"tcp_connections":c.dials.Load(),"error_samples":errs});time.Sleep(*hold);return nil}
        if len(errs)>0{return fmt.Errorf("tunnel setup: %v",errs)}
    }
    payload:=bytes.Repeat([]byte("x"),*size)
    phase:=func(d time.Duration)result{
        var mu sync.Mutex;var wg sync.WaitGroup;var latencies []float64;var samples []string;errors:=0
        start:=time.Now();deadline:=start.Add(d)
        for i:=0;i<*concurrency;i++{wg.Add(1);go func(i int){
            defer wg.Done();recv:=make([]byte,*size);var local []float64;localErrors:=0;var localSamples []string
            for time.Now().Before(deadline){
                t:=time.Now();var e error
                if *kind=="http"{_,e=c.request(i,payload,recv)}else{e=tunnels[i].exchange(payload,recv)}
                if e!=nil{localErrors++;if len(localSamples)<2{localSamples=append(localSamples,e.Error())};time.Sleep(time.Millisecond)}else{local=append(local,float64(time.Since(t).Nanoseconds())/1e6)}
            }
            mu.Lock();latencies=append(latencies,local...);errors+=localErrors
            for _,s:=range localSamples{if len(samples)<5{samples=append(samples,s)}};mu.Unlock()
        }(i)}
        wg.Wait();elapsed:=time.Since(start).Seconds();sort.Float64s(latencies)
        pct:=func(q float64)float64{if len(latencies)==0{return 0};i:=int(float64(len(latencies)-1)*q);return latencies[i]}
        return result{Success:len(latencies),Errors:errors,ErrorSamples:samples,Seconds:elapsed,RequestsPerSecond:float64(len(latencies))/elapsed,
            MiBPerSecond:float64(len(latencies))*float64(*size)/(1<<20)/elapsed,P50:pct(.50),P95:pct(.95),P99:pct(.99),
            Protocol:*protocol,Concurrency:*concurrency,BodyBytes:*size}
    }
    warm:=phase(*warmup)
    r:=phase(*duration);r.Dials=c.dials.Load();r.WarmupSuccess=warm.Success;r.WarmupErrors=warm.Errors
    emit(r)
    return nil
}
